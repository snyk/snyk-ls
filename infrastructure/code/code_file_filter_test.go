/*
 * © 2026 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package code

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	gafUtils "github.com/snyk/go-application-framework/pkg/utils"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

// collectRelPaths returns the kept files as folder-relative, slash-separated paths.
func collectRelPaths(t *testing.T, root types.FilePath, ch <-chan string) []string {
	t.Helper()

	// Eventually rather than a plain range: a channel the filter never closes then fails here by
	// name, instead of hanging until the whole package times out.
	var abs []string
	require.Eventually(t, func() bool {
		abs = util.ChannelToSlice(ch)
		return true
	}, 30*time.Second, time.Millisecond, "channel was never closed")

	out := make([]string, 0, len(abs))
	for _, f := range abs {
		// GAF resolves symlinks, so on macOS a mismatch shows up as "../../private/var/..." in the
		// diff. Fail on the cause instead.
		require.True(t, strings.HasPrefix(f, string(root)), "file %q must be under root %q", f, root)
		rel, err := filepath.Rel(string(root), f)
		require.NoError(t, err)
		out = append(out, filepath.ToSlash(rel))
	}
	return out
}

func runDispatch(t *testing.T, sc *Scanner, root types.FilePath) []string {
	t.Helper()

	folderConfig := config.GetFolderConfigFromEngine(sc.engine, sc.configResolver, root, sc.logger)

	ch, err := sc.filteredFiles(folderConfig, *sc.logger)
	require.NoError(t, err)
	return collectRelPaths(t, root, ch)
}

// stageFilterFlags writes the file filter flags for root, which is where the dispatcher reads them.
// Flag values live in configuration keyed by folder path, so any folder config for root sees them.
func stageFilterFlags(t *testing.T, sc *Scanner, root types.FilePath, trackedFiles, metacharFix bool) {
	t.Helper()
	stageAllFilterFlags(t, sc, root, trackedFiles, metacharFix, false)
}

func stageAllFilterFlags(t *testing.T, sc *Scanner, root types.FilePath, trackedFiles, metacharFix, skipSymlinks bool) {
	t.Helper()

	folderConfig := config.GetFolderConfigFromEngine(sc.engine, sc.configResolver, root, sc.logger)
	folderConfig.SetFeatureFlag(gafUtils.FF_GITIGNORE_RESPECT_TRACKED_FILES, trackedFiles)
	folderConfig.SetFeatureFlag(gafUtils.FF_FILE_FILTER_METACHARACTER_FIX, metacharFix)
	folderConfig.SetFeatureFlag(gafUtils.FF_FILE_FILTER_SKIP_SYMLINKS, skipSymlinks)
}

// filterFixture describes a folder to scan. nestedDir puts the scan root under an extra path
// segment, for paths that need specific characters in them.
type filterFixture struct {
	nestedDir string
	tree      map[string]string
	ruleFiles map[string]string
	tracked   []string
	initGit   bool
}

func setupFilterFixture(t *testing.T, f filterFixture) types.FilePath {
	t.Helper()

	root := filepath.Join(t.TempDir(), f.nestedDir)
	for relPath, content := range f.tree {
		writeFixtureFile(t, filepath.Join(root, relPath), content)
	}

	if f.initGit {
		repo, err := git.PlainInit(root, false)
		require.NoError(t, err)
		worktree, err := repo.Worktree()
		require.NoError(t, err)
		for _, path := range f.tracked {
			_, err = worktree.Add(path)
			require.NoError(t, err)
		}
	}

	// Rule files are written after staging so they stay untracked unless named in tracked.
	for relPath, content := range f.ruleFiles {
		writeFixtureFile(t, filepath.Join(root, relPath), content)
	}

	return types.FilePath(root)
}

func writeFixtureFile(t *testing.T, path string, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

// Test_filteredFiles_withoutFolderConfigFails covers the flags being unreadable: filtering has to say
// so rather than read them as off, which would filter the folder as though the rollout had never
// reached it and leave nothing behind to explain why.
func Test_filteredFiles_withoutFolderConfigFails(t *testing.T) {
	sc, _ := setupTestScanner(t)

	ch, err := sc.filteredFiles(nil, *sc.logger)

	require.Error(t, err)
	assert.Nil(t, ch)
}

// Fixture file names describe how each file is meant to be treated, so an expected set can be read
// without cross-referencing the rule files: *.gitignored_ext matches the .gitignore rule,
// *.dcignored_ext the .dcignore rule, and never_ignored.js matches no rule at all.
const (
	neverIgnoredFile = "never_ignored.js"
	snykExcludedFile = "snyk_excluded.js"
	gitignoreRule    = "*.gitignored_ext\n"
	dcignoreRule     = "*.dcignored_ext\n"
	snykExcludeRule  = "# Snyk (https://snyk.io) policy file\n" +
		"version: v1.25.1\n" +
		"ignore: {}\n" +
		"exclude:\n" +
		"  code:\n" +
		"    - " + snykExcludedFile + "\n"
)

// dirtyRepo is a git repo where a gitignored file is tracked anyway, next to an untracked file the
// same rule matches. Only the tracked one is affected by the rollout.
func dirtyRepo() filterFixture {
	return filterFixture{
		tree: map[string]string{
			neverIgnoredFile:                           "console.log('app');\n",
			"git_tracked.gitignored_ext":               "tracked\n",
			"not_git_tracked.gitignored_ext":           "untracked\n",
			"gitignored_dir/file_in_gitignored_dir.js": "generated\n",
			".DS_Store":     "ds\n",
			"sub/.DS_Store": "ds\n",
			".svn/entries":  "svn\n",
			".hg/store":     "hg\n",
			".bzr/branch":   "bzr\n",
		},
		ruleFiles: map[string]string{".gitignore": gitignoreRule + "gitignored_dir/\n"},
		tracked:   []string{"git_tracked.gitignored_ext"},
		initGit:   true,
	}
}

// metaCharRepo is dirtyRepo under a directory name containing regex metacharacters, the shape that
// broke customers on OneDrive and SharePoint paths.
func metaCharRepo() filterFixture {
	return filterFixture{
		nestedDir: filepath.Join("OneDrive - Foobar (Team1)", "repo"),
		tree: map[string]string{
			neverIgnoredFile:             "console.log('app');\n",
			"node_modules/dependency.js": "module.exports = {};\n",
			"git_tracked.gitignored_ext": "tracked\n",
		},
		ruleFiles: map[string]string{".gitignore": "node_modules\n" + gitignoreRule},
		tracked:   []string{"git_tracked.gitignored_ext"},
		initGit:   true,
	}
}

// trackedAgainstEveryIgnoreFile tracks one file per rule file format. Being tracked by git is only
// meant to rescue a file from .gitignore, so the .dcignore and .snyk exclusions must still apply.
func trackedAgainstEveryIgnoreFile() filterFixture {
	return filterFixture{
		tree: map[string]string{
			neverIgnoredFile:             "console.log('app');\n",
			"git_tracked.gitignored_ext": "tracked and gitignored\n",
			"git_tracked.dcignored_ext":  "tracked and dcignored\n",
			snykExcludedFile:             "tracked and snyk excluded\n",
		},
		ruleFiles: map[string]string{
			".gitignore": gitignoreRule,
			".dcignore":  dcignoreRule,
			".snyk":      snykExcludeRule,
		},
		tracked: []string{
			neverIgnoredFile,
			"git_tracked.gitignored_ext",
			"git_tracked.dcignored_ext",
			snykExcludedFile,
		},
		initGit: true,
	}
}

func noIgnoreFiles() filterFixture {
	return filterFixture{
		tree: map[string]string{
			neverIgnoredFile:           "console.log('app');\n",
			"src/never_ignored_too.go": "package main\n",
		},
	}
}

// vcsJunkOnly has no ignore files, so every exclusion here has to come from lsDefaultIgnoredRules
// (plus GAF's own .git rule). Directories are named after version control systems but are not real
// repositories.
func vcsJunkOnly() filterFixture {
	return filterFixture{
		tree: map[string]string{
			neverIgnoredFile:           "console.log('app');\n",
			"sub/never_ignored_too.js": "console.log('app2');\n",
			".DS_Store":                "ds\n",
			"sub/.DS_Store":            "ds\n",
			".svn/entries":             "svn\n",
			".hg/store":                "hg\n",
			".bzr/branch":              "bzr\n",
			".git/config":              "git\n",
		},
	}
}

// plainIgnores exercises all three rule file formats at once, with nothing tracked by git.
func plainIgnores() filterFixture {
	return filterFixture{
		tree: map[string]string{
			neverIgnoredFile:                         "console.log('app');\n",
			"a_file.gitignored_ext":                  "gitignored\n",
			"dcignored_dir/file_in_dcignored_dir.js": "dcignored\n",
			snykExcludedFile:                         "snyk excluded\n",
		},
		ruleFiles: map[string]string{
			".gitignore": gitignoreRule,
			".dcignore":  "dcignored_dir/\n",
			".snyk":      snykExcludeRule,
		},
	}
}

// Test_filteredFiles pins which files reach a scan for each combination of the two file filter
// feature flags. The flag combinations are the rollout states a customer can be in, so a row going
// red means some org's scan set has moved.
//
// No t.Parallel(): setupTestScanner sets the process-wide zerolog level and an environment variable,
// so these cannot run concurrently.
func Test_filteredFiles(t *testing.T) {
	cases := []struct {
		name           string
		fixture        filterFixture
		trackedFilesFF bool
		metacharFF     bool
		want           []string
	}{
		{
			name:    "vcs junk excluded, tracked files off",
			fixture: vcsJunkOnly(),
			want:    []string{neverIgnoredFile, "sub/never_ignored_too.js"},
		},
		{
			name:           "vcs junk excluded, tracked files on",
			fixture:        vcsJunkOnly(),
			trackedFilesFF: true,
			want:           []string{neverIgnoredFile, "sub/never_ignored_too.js"},
		},
		{
			name:    "no ignore files, tracked files off",
			fixture: noIgnoreFiles(),
			want:    []string{neverIgnoredFile, "src/never_ignored_too.go"},
		},
		{
			name:           "no ignore files, tracked files on",
			fixture:        noIgnoreFiles(),
			trackedFilesFF: true,
			want:           []string{neverIgnoredFile, "src/never_ignored_too.go"},
		},
		{
			name:    "gitignore, dcignore and snyk rules all applied, tracked files off",
			fixture: plainIgnores(),
			want:    []string{".gitignore", ".dcignore", ".snyk", neverIgnoredFile},
		},
		{
			name:           "gitignore, dcignore and snyk rules all applied, tracked files on",
			fixture:        plainIgnores(),
			trackedFilesFF: true,
			want:           []string{".gitignore", ".dcignore", ".snyk", neverIgnoredFile},
		},
		{
			name:    "tracked but gitignored file dropped when tracked files off",
			fixture: dirtyRepo(),
			want:    []string{".gitignore", neverIgnoredFile},
		},
		{
			name:           "tracked but gitignored file kept when tracked files on",
			fixture:        dirtyRepo(),
			trackedFilesFF: true,
			want:           []string{".gitignore", neverIgnoredFile, "git_tracked.gitignored_ext"},
		},
		// Under a path containing regex metacharacters, an unfixed .gitignore excludes nothing at
		// all: the directory's parens are folded into every glob built from that file, and
		// go-gitignore compiles globs to regexes, so the parens become a capture group instead of
		// literal characters. The pattern then only matches a path with the parens removed, which no
		// real file has. So in the two rows below node_modules and the gitignored file both survive,
		// and only the third row keeps the tracked file for the reason the rollout is about.
		//
		// The first row is also what the two flags being independent on the platform costs here: the
		// metacharacter fix only ever reaches a filter built on the new path, so on its own it changes
		// nothing, and a customer needs the tracked files flag as well to get it.
		{
			name:       "metacharacter path, only the metacharacter fix on, keeps legacy filtering",
			fixture:    metaCharRepo(),
			metacharFF: true,
			want: []string{".gitignore", neverIgnoredFile, "node_modules/dependency.js",
				"git_tracked.gitignored_ext"},
		},
		{
			name:           "metacharacter path, unfixed gitignore excludes nothing",
			fixture:        metaCharRepo(),
			trackedFilesFF: true,
			want: []string{".gitignore", neverIgnoredFile, "node_modules/dependency.js",
				"git_tracked.gitignored_ext"},
		},
		{
			name:           "metacharacter path, both flags on, rules apply and tracked file survives",
			fixture:        metaCharRepo(),
			trackedFilesFF: true,
			metacharFF:     true,
			want:           []string{".gitignore", neverIgnoredFile, "git_tracked.gitignored_ext"},
		},
		{
			name:    "tracked files excluded by every ignore file format, tracked files off",
			fixture: trackedAgainstEveryIgnoreFile(),
			want:    []string{".gitignore", ".dcignore", ".snyk", neverIgnoredFile},
		},
		{
			// Only the .gitignore rule gives way to git tracking: dcignore and snyk excludes are
			// Snyk's own scan scoping, so they keep excluding a file git happens to track.
			name:           "tracked files excluded by every ignore file format, tracked files on",
			fixture:        trackedAgainstEveryIgnoreFile(),
			trackedFilesFF: true,
			want: []string{".gitignore", ".dcignore", ".snyk", neverIgnoredFile,
				"git_tracked.gitignored_ext"},
		},
		{
			name:    "empty folder yields nothing",
			fixture: filterFixture{},
			want:    nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc, _ := setupTestScanner(t)

			root := setupFilterFixture(t, tc.fixture)
			stageFilterFlags(t, sc, root, tc.trackedFilesFF, tc.metacharFF)

			assert.ElementsMatch(t, tc.want, runDispatch(t, sc, root))
		})
	}
}

// Test_filteredFiles_resolvesFlagPerFolder covers a workspace where one folder has the rollout and
// another does not, which is the normal state part-way through a rollout.
//
// It does not cover per-folder organization resolution; the flag values here are written straight
// into folder metadata rather than fetched per org.
func Test_filteredFiles_resolvesFlagPerFolder(t *testing.T) {
	sc, engine := setupTestScanner(t)
	logger := engine.GetLogger()
	resolver := sc.configResolver

	// The real service, not the fake, because the fake ignores the folder it is asked about.
	sc.featureFlagService = featureflag.New(engine.GetConfiguration(), logger, engine, resolver)

	folderOn := setupFilterFixture(t, dirtyRepo())
	folderOff := setupFilterFixture(t, dirtyRepo())

	fcOn := config.GetFolderConfigFromEngine(engine, resolver, folderOn, logger)
	fcOn.SetFeatureFlag(gafUtils.FF_GITIGNORE_RESPECT_TRACKED_FILES, true)

	fcOff := config.GetFolderConfigFromEngine(engine, resolver, folderOff, logger)
	fcOff.SetFeatureFlag(gafUtils.FF_GITIGNORE_RESPECT_TRACKED_FILES, false)

	resultOn := runDispatch(t, sc, folderOn)
	resultOff := runDispatch(t, sc, folderOff)

	require.NotEmpty(t, resultOn)
	require.NotEmpty(t, resultOff)
	assert.Contains(t, resultOn, neverIgnoredFile)
	assert.Contains(t, resultOff, neverIgnoredFile)

	assert.Contains(t, resultOn, "git_tracked.gitignored_ext", "the folder with the flag on must keep the tracked-but-gitignored file")
	assert.NotContains(t, resultOff, "git_tracked.gitignored_ext", "the folder with the flag off must not keep the tracked-but-gitignored file")
}

func Test_legacyFilteredFiles_cachesFileFilterPerFolder(t *testing.T) {
	sc, _ := setupTestScanner(t)
	root := setupFilterFixture(t, dirtyRepo())

	ch, err := sc.legacyFilteredFiles(root, *sc.logger)
	require.NoError(t, err)
	got := collectRelPaths(t, root, ch)
	assert.ElementsMatch(t, []string{".gitignore", neverIgnoredFile}, got)
	assert.Equal(t, 1, sc.fileFilters.Size(), "the legacy path must cache exactly one FileFilter for this folder")

	cachedFilter, ok := sc.fileFilters.Load(string(root))
	require.True(t, ok)
	require.NotNil(t, cachedFilter)

	ch2, err := sc.legacyFilteredFiles(root, *sc.logger)
	require.NoError(t, err)
	got2 := collectRelPaths(t, root, ch2)
	assert.ElementsMatch(t, []string{".gitignore", neverIgnoredFile}, got2)
	assert.Equal(t, 1, sc.fileFilters.Size())

	cachedFilterAgain, ok := sc.fileFilters.Load(string(root))
	require.True(t, ok)
	assert.Same(t, cachedFilter, cachedFilterAgain, "a second legacy call for the same folder must reuse the same *FileFilter pointer")
}

// Test_newFilteredFiles_doesNotCacheFileFilter guards a deliberate difference from the legacy path.
// A FileFilter holds the configuration it was built with, so a cached one would keep serving the
// feature flag values resolved on the folder's first scan: enabling or disabling the rollout, or
// switching the folder to a different organization, would not take effect until the language server
// restarted. Each filter also carries its own metric scope, which per-scan analytics need.
func Test_newFilteredFiles_doesNotCacheFileFilter(t *testing.T) {
	sc, _ := setupTestScanner(t)
	root := setupFilterFixture(t, dirtyRepo())

	ch, err := sc.newFilteredFiles(config.GetFolderConfigFromEngine(sc.engine, sc.configResolver, root, sc.logger), *sc.logger)
	require.NoError(t, err)
	got := collectRelPaths(t, root, ch)

	assert.ElementsMatch(t, []string{".gitignore", neverIgnoredFile, "git_tracked.gitignored_ext"}, got)
	assert.Equal(t, 0, sc.fileFilters.Size(), "the new path must not cache a FileFilter")
}

// Test_filteredFiles_reReadsTrackedFilesFlagPerCall covers a folder already scanned before the
// rollout reached it: enabling the flag must change the next scan of that same folder, and the
// filter cached by the earlier scan must not be reused. This is why the new path caches nothing.
func Test_filteredFiles_reReadsTrackedFilesFlagPerCall(t *testing.T) {
	sc, _ := setupTestScanner(t)

	root := setupFilterFixture(t, dirtyRepo())
	stageFilterFlags(t, sc, root, false, false)

	legacyResult := runDispatch(t, sc, root)
	assert.ElementsMatch(t, []string{".gitignore", neverIgnoredFile}, legacyResult)

	cachedFilter, ok := sc.fileFilters.Load(string(root))
	require.True(t, ok, "the legacy call must have cached a FileFilter for this folder")
	require.NotNil(t, cachedFilter)

	stageFilterFlags(t, sc, root, true, false)

	newResult := runDispatch(t, sc, root)
	assert.ElementsMatch(t, []string{".gitignore", neverIgnoredFile, "git_tracked.gitignored_ext"}, newResult,
		"after flipping the flag on, the same folder must take the new path")

	cachedFilterAfter, ok := sc.fileFilters.Load(string(root))
	require.True(t, ok)
	// Identity, not Size: a size of one is equally true if the entry was replaced.
	assert.Same(t, cachedFilter, cachedFilterAfter,
		"the stale legacy cache entry must not be replaced or mutated by the new path, which does not cache at all")
}

// Test_newFilteredFiles_doesNotMutateEngineConfig guards against one folder's flag values leaking
// into every other folder and scan, which is what setting them on the engine config would do.
func Test_newFilteredFiles_doesNotMutateEngineConfig(t *testing.T) {
	sc, engine := setupTestScanner(t)
	root := setupFilterFixture(t, dirtyRepo())

	conf := engine.GetConfiguration()
	require.False(t, conf.IsSet(gafUtils.FF_FILE_FILTER_METACHARACTER_FIX))
	require.False(t, conf.IsSet(gafUtils.FF_GITIGNORE_RESPECT_TRACKED_FILES))

	ch, err := sc.newFilteredFiles(config.GetFolderConfigFromEngine(sc.engine, sc.configResolver, root, sc.logger), *sc.logger)
	require.NoError(t, err)
	kept := collectRelPaths(t, root, ch)
	assert.ElementsMatch(t, []string{".gitignore", neverIgnoredFile, "git_tracked.gitignored_ext"}, kept)

	assert.False(t, conf.IsSet(gafUtils.FF_FILE_FILTER_METACHARACTER_FIX), "newFilteredFiles must not leak its config.Set calls into the parent engine configuration")
	assert.False(t, conf.IsSet(gafUtils.FF_GITIGNORE_RESPECT_TRACKED_FILES), "newFilteredFiles must not leak its config.Set calls into the parent engine configuration")
}

// Test_newFilteredFiles_scopesConfigurationToFolderOrganization covers the configuration handed to the
// file filter, not just the two flag values read off it: anything the filter resolves for itself must
// answer for the folder being scanned. The folder's organization is observed through MAX_THREADS
// because that is a key this path genuinely reads from the clone.
func Test_newFilteredFiles_scopesConfigurationToFolderOrganization(t *testing.T) {
	const globalOrg = "00000000-0000-0000-0000-000000000002"
	const folderOrg = "00000000-0000-0000-0000-000000000001"

	sc, engine := setupTestScanner(t)
	root := setupFilterFixture(t, dirtyRepo())

	conf := engine.GetConfiguration()
	types.SetGlobalUser(conf, types.SettingPreferredOrg, globalOrg)
	types.SetPreferredOrgAndOrgSetByUser(conf, root, folderOrg, true)

	var mu sync.Mutex
	var observedOrgs []string
	conf.AddDefaultValue(configuration.MAX_THREADS, func(c configuration.Configuration, existingValue any) (any, error) {
		mu.Lock()
		observedOrgs = append(observedOrgs, c.GetString(configuration.ORGANIZATION))
		mu.Unlock()
		return existingValue, nil
	})

	ch, err := sc.newFilteredFiles(config.GetFolderConfigFromEngine(sc.engine, sc.configResolver, root, sc.logger), *sc.logger)
	require.NoError(t, err)
	collectRelPaths(t, root, ch)

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, observedOrgs, "newFilteredFiles must read MAX_THREADS from the configuration it hands to the file filter")
	for _, org := range observedOrgs {
		assert.Equal(t, folderOrg, org, "the configuration handed to the file filter must carry the scanned folder's organization")
	}
}

// Test_filteredFiles_unreadableRuleFileReturnsError pins that an unreadable ignore file fails the
// scan rather than silently scanning files the customer expected to be excluded.
func Test_filteredFiles_unreadableRuleFileReturnsError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod 0000 does not reliably restrict file readability on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root can read files regardless of permissions")
	}

	for _, trackedFilesFF := range []bool{false, true} {
		name := "legacyPath"
		if trackedFilesFF {
			name = "newPath"
		}
		t.Run(name, func(t *testing.T) {
			sc, _ := setupTestScanner(t)

			root := setupFilterFixture(t, filterFixture{
				tree:      map[string]string{neverIgnoredFile: "console.log('app');\n"},
				ruleFiles: map[string]string{".gitignore": gitignoreRule},
			})
			stageFilterFlags(t, sc, root, trackedFilesFF, false)

			gitignorePath := filepath.Join(string(root), ".gitignore")
			require.NoError(t, os.Chmod(gitignorePath, 0o000))
			// Restore permissions or t.TempDir()'s cleanup cannot remove the fixture tree.
			t.Cleanup(func() { _ = os.Chmod(gitignorePath, 0o600) })

			folderConfig := config.GetFolderConfigFromEngine(sc.engine, sc.configResolver, root, sc.logger)

			ch, err := sc.filteredFiles(folderConfig, *sc.logger)
			require.Error(t, err)
			require.Nil(t, ch)
		})
	}
}

// Test_filteredFiles_scanRootIsSubdirectoryOfGitRepo covers opening a subfolder of a repository
// rather than its root, which is common in monorepos: tracked files must still be recognized when
// the .git directory sits above the scanned folder.
func Test_filteredFiles_scanRootIsSubdirectoryOfGitRepo(t *testing.T) {
	sc, _ := setupTestScanner(t)

	repoRoot := t.TempDir()
	writeFixtureFile(t, filepath.Join(repoRoot, neverIgnoredFile), "console.log('app');\n")
	writeFixtureFile(t, filepath.Join(repoRoot, "sub", "git_tracked.gitignored_ext"), "tracked\n")
	writeFixtureFile(t, filepath.Join(repoRoot, "sub", "not_git_tracked.gitignored_ext"), "untracked\n")

	repo, err := git.PlainInit(repoRoot, false)
	require.NoError(t, err)
	worktree, err := repo.Worktree()
	require.NoError(t, err)
	_, err = worktree.Add(neverIgnoredFile)
	require.NoError(t, err)
	_, err = worktree.Add("sub/git_tracked.gitignored_ext")
	require.NoError(t, err)

	// Written after staging so it stays untracked, and inside the scanned subdirectory because the
	// filter only walks files under the scan root.
	writeFixtureFile(t, filepath.Join(repoRoot, "sub", ".gitignore"), gitignoreRule)

	scanRoot := types.FilePath(filepath.Join(repoRoot, "sub"))
	stageFilterFlags(t, sc, scanRoot, true, false)

	got := runDispatch(t, sc, scanRoot)

	assert.ElementsMatch(t, []string{".gitignore", "git_tracked.gitignored_ext"}, got,
		"the tracked file must be preserved and the untracked one dropped, even though the git "+
			"repository root is above the scanned subdirectory")
}

// Test_lsDefaultIgnoredRules_excludesEachDocumentedPattern keeps version control and editor
// metadata out of the files uploaded for scanning, one row per pattern so a regression names the
// pattern that broke.
func Test_lsDefaultIgnoredRules_excludesEachDocumentedPattern(t *testing.T) {
	testCases := []struct {
		name            string
		pattern         string
		excludedRelPath string
	}{
		// GAF applies **/.git/** itself, so this row would still pass with our copy of the pattern
		// removed. It stays to document that .git is excluded, whoever excludes it.
		{name: "git", pattern: "**/.git/**", excludedRelPath: "sub/.git/config"},
		{name: "svn", pattern: "**/.svn/**", excludedRelPath: "sub/.svn/entries"},
		{name: "hg", pattern: "**/.hg/**", excludedRelPath: "sub/.hg/store"},
		{name: "bzr", pattern: "**/.bzr/**", excludedRelPath: "sub/.bzr/branch"},
		{name: "dsstore", pattern: "**/.DS_Store/**", excludedRelPath: "sub/.DS_Store"},
	}

	require.Len(t, testCases, len(lsDefaultIgnoredRules),
		"lsDefaultIgnoredRules has changed: add or remove a row here so every rule still has a case proving it excludes something")

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sc, _ := setupTestScanner(t)
			root := setupFilterFixture(t, filterFixture{tree: map[string]string{
				neverIgnoredFile:   "console.log('app');\n",
				tc.excludedRelPath: "junk\n",
			}})

			got := runDispatch(t, sc, root)

			assert.ElementsMatch(t, []string{neverIgnoredFile}, got, "pattern %s must exclude %s", tc.pattern, tc.excludedRelPath)
		})
	}
}

// Test_filteredFiles_defaultRulesDoNotAliasAcrossFolders scans two folders with one scanner, as a
// multi-root workspace does, and pins that the first folder's rules do not carry into the second.
func Test_filteredFiles_defaultRulesDoNotAliasAcrossFolders(t *testing.T) {
	sc, _ := setupTestScanner(t)

	rootA := setupFilterFixture(t, filterFixture{
		tree:      map[string]string{neverIgnoredFile: "a\n", "gitignored_in_folder_a_only.txt": "secret\n"},
		ruleFiles: map[string]string{".gitignore": "gitignored_in_folder_a_only.txt\n"},
	})

	rootB := setupFilterFixture(t, filterFixture{
		tree: map[string]string{neverIgnoredFile: "b\n", "gitignored_in_folder_a_only.txt": "should stay in B\n"},
	})

	gotA := runDispatch(t, sc, rootA)
	assert.ElementsMatch(t, []string{neverIgnoredFile, ".gitignore"}, gotA)

	gotB := runDispatch(t, sc, rootB)
	assert.ElementsMatch(t, []string{neverIgnoredFile, "gitignored_in_folder_a_only.txt"}, gotB,
		"folder A's own-file exclusion rule must not leak into folder B scanned afterwards by the same scanner")
}

func Test_filteredFiles_skipsSymlinksWhenFlagEnabled(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require elevated privileges on Windows")
	}

	sc, _ := setupTestScanner(t)

	root := t.TempDir()
	writeFixtureFile(t, filepath.Join(root, neverIgnoredFile), "console.log('app');\n")

	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "secret.js")
	writeFixtureFile(t, outsideFile, "module.exports = 'leaked';\n")

	require.NoError(t, os.Symlink(outsideFile, filepath.Join(root, "link_to_outside.js")))

	rootPath := types.FilePath(root)

	t.Run("symlink included when flag is off", func(t *testing.T) {
		stageAllFilterFlags(t, sc, rootPath, true, false, false)
		got := runDispatch(t, sc, rootPath)
		assert.Contains(t, got, "link_to_outside.js")
	})

	t.Run("symlink skipped when flag is on", func(t *testing.T) {
		stageAllFilterFlags(t, sc, rootPath, true, false, true)
		got := runDispatch(t, sc, rootPath)
		assert.NotContains(t, got, "link_to_outside.js")
		assert.Contains(t, got, neverIgnoredFile)
	})
}
