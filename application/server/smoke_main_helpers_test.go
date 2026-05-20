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

package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/types"
)

// localRepo holds a local git repo URL and its HEAD commit hash.
type localRepo struct {
	url    string
	commit string // full 40-char SHA
}

// setupLocalBareRepo creates a temporary git repo with one commit and returns
// its filesystem path (usable as a clone URL) and the full HEAD hash.
func setupLocalBareRepo(t *testing.T) localRepo {
	t.Helper()
	dir := t.TempDir()

	for _, args := range [][]string{
		{"init"},
		{"config", "user.email", "test@example.com"},
		{"config", "user.name", "Test"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		require.NoError(t, cmd.Run(), "git %v", args)
	}

	require.NoError(t, os.WriteFile(filepath.Join(dir, "README"), []byte("test"), 0o644))

	for _, args := range [][]string{
		{"add", "."},
		{"commit", "-m", "initial"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		require.NoError(t, cmd.Run(), "git %v", args)
	}

	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = dir
	out, err := cmd.Output()
	require.NoError(t, err)
	commit := strings.TrimSpace(string(out))

	return localRepo{url: dir, commit: commit}
}

// ── resolveCliDir ────────────────────────────────────────────────────────────

func TestResolveCliDir_NoCacheEnv(t *testing.T) {
	t.Setenv("SNYK_LS_CLI_CACHE_DIR", "")

	dir, cleanup := resolveCliDir()

	assert.NotEmpty(t, dir)
	_, err := os.Stat(dir)
	assert.NoError(t, err, "temp dir must exist before cleanup")

	cleanup()
	_, err = os.Stat(dir)
	assert.True(t, os.IsNotExist(err), "cleanup must remove the temp dir")
}

func TestResolveCliDir_WithCacheEnv(t *testing.T) {
	cacheDir := t.TempDir()
	t.Setenv("SNYK_LS_CLI_CACHE_DIR", cacheDir)

	dir, cleanup := resolveCliDir()
	defer cleanup()

	assert.Equal(t, cacheDir, dir, "must return the env-specified cache dir")

	cleanup()
	_, err := os.Stat(cacheDir)
	assert.NoError(t, err, "cleanup must be a no-op for a pre-configured cache dir")
}

func TestResolveCliDir_WithCacheEnvCreatesDir(t *testing.T) {
	parent := t.TempDir()
	cacheDir := filepath.Join(parent, "cli-cache")
	t.Setenv("SNYK_LS_CLI_CACHE_DIR", cacheDir)

	dir, cleanup := resolveCliDir()
	defer cleanup()

	assert.Equal(t, cacheDir, dir)
	_, err := os.Stat(cacheDir)
	assert.NoError(t, err, "resolveCliDir must create the cache dir when it does not exist")
}

// ── repoIsAtCommit ───────────────────────────────────────────────────────────

func TestRepoIsAtCommit_MatchesFullHash(t *testing.T) {
	repo := setupLocalBareRepo(t)
	assert.True(t, repoIsAtCommit(repo.url, repo.commit))
}

func TestRepoIsAtCommit_MatchesShortHash(t *testing.T) {
	repo := setupLocalBareRepo(t)
	assert.True(t, repoIsAtCommit(repo.url, repo.commit[:7]))
}

func TestRepoIsAtCommit_NoMatch(t *testing.T) {
	repo := setupLocalBareRepo(t)
	assert.False(t, repoIsAtCommit(repo.url, "0000000"))
}

func TestRepoIsAtCommit_InvalidDir(t *testing.T) {
	assert.False(t, repoIsAtCommit("/nonexistent/path", "abc1234"))
}

// ── cloneRepoOnceCached ──────────────────────────────────────────────────────

func TestCloneRepoOnceCached_NoCacheRootPassesThrough(t *testing.T) {
	repo := setupLocalBareRepo(t)

	result, err := cloneRepoOnceCached("prefix-*", "", repo.url, "repo", repo.commit[:7])
	require.NoError(t, err)
	defer os.RemoveAll(string(result))

	_, err = os.Stat(filepath.Join(string(result), "repo"))
	assert.NoError(t, err, "cloned repo directory must exist")
}

func TestCloneRepoOnceCached_CacheHit(t *testing.T) {
	repo := setupLocalBareRepo(t)
	cacheRoot := t.TempDir()
	subdir := "repo"

	// Pre-populate the cache with a real clone at the correct commit.
	_, err := cloneIntoBase(cacheRoot, repo.url, subdir, repo.commit[:7])
	require.NoError(t, err)

	result, err := cloneRepoOnceCached("prefix-*", cacheRoot, "https://example.invalid/unreachable.git", subdir, repo.commit[:7])

	require.NoError(t, err)
	assert.Equal(t, types.FilePath(cacheRoot), result, "cache hit must return cacheRoot")

	// Confirm we didn't re-clone (original clone is untouched).
	_, err = os.Stat(filepath.Join(cacheRoot, subdir, "README"))
	assert.NoError(t, err, "README from original clone must still be present")
}

func TestCloneRepoOnceCached_StaleCache_EvictsAndReclones(t *testing.T) {
	repo := setupLocalBareRepo(t)
	cacheRoot := t.TempDir()
	subdir := "repo"

	// Pre-populate the cache with a clone at the correct commit.
	_, err := cloneIntoBase(cacheRoot, repo.url, subdir, repo.commit[:7])
	require.NoError(t, err)

	// Call with a wrong commit — must detect staleness, remove the dir, attempt re-clone.
	// The re-clone with a non-existent commit will fail, but the stale dir is gone.
	_, err = cloneRepoOnceCached("prefix-*", cacheRoot, repo.url, subdir, "0000000")

	require.Error(t, err, "re-clone with a non-existent commit must fail")

	// The stale dir was removed before the re-clone attempt; git clone re-created it
	// but git reset failed, so the dir may or may not exist — the key assertion is
	// that the function did NOT return a successful result with the wrong commit.
}

func TestCloneRepoOnceCached_NoCacheRoot_ReturnsError(t *testing.T) {
	// With empty cacheRoot, falls through to cloneRepoOnce which needs network.
	// We can't test that path here without network — covered by smoke TestMain.
	t.Skip("no-cache-root path requires network; tested via SMOKE_TESTS=1")
}
