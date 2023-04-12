package filefilter

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	ignore "github.com/sabhiram/go-gitignore"
	"gopkg.in/yaml.v3"
)

func FindNonIgnoredFiles(rootFolder string) <-chan string {
	return newFileFilter(rootFolder).findNonIgnoredFiles()
}

type fileFilter struct {
	// The path to the root of the repository
	repoRoot               string
	ignoreFiles            []string
	globsPerFolder         map[string][]string
	ignoreCheckerPerFolder map[string]ignore.IgnoreParser
	logger                 zerolog.Logger
}

func newFileFilter(rootFolder string) *fileFilter {
	return &fileFilter{
		repoRoot:               rootFolder,
		ignoreFiles:            []string{".gitignore", ".dcignore", ".snyk"},
		globsPerFolder:         make(map[string][]string),
		ignoreCheckerPerFolder: make(map[string]ignore.IgnoreParser),
		logger:                 log.With().Str("component", "fileFilter").Str("repoRoot", rootFolder).Logger(),
	}
}

func (f *fileFilter) findNonIgnoredFiles() <-chan string {
	resultsCh := make(chan string)
	var wg sync.WaitGroup
	go func() {
		defer close(resultsCh)
		// When walking a directory, the iteration is the directory itself (`path` parameter is the directory path).
		// The ignore files are immediately parsed, and the iterations of the files come after the ignore rules have been loaded
		err := filepath.WalkDir(f.repoRoot, func(path string, dirEntry os.DirEntry, err error) error {
			if err != nil {
				// err is not nil only when d is a directory that coult not be read,
				// so a message is logged and the directory is skipped.
				f.logger.Err(err).Msg("Error during file traversal of directory \"" + path + "\"\n" +
					"Skipping Directory")
				return filepath.SkipDir
			}
			if dirEntry == nil {
				return nil
			}

			if dirEntry.IsDir() {
				// The following optimization has been removed because it doesn't take into account negation rules:
				// For example:
				// .ignoreme
				// !.ignoreme/keepme.txt
				//
				// This implementation would skip the entire folder and not return keepme.txt:
				//
				// ```
				//parentFolderPath := filepath.Dir(path)
				//if path != rootFolder && ignoreCheckerPerFolder[parentFolderPath].MatchesPath(path) {
				//	return filepath.SkipDir
				//}
				// ```
				globs := f.collectGlobs(path)
				f.globsPerFolder[path] = globs
				f.ignoreCheckerPerFolder[path] = ignore.CompileIgnoreLines(globs...)
				return nil
			} else {
				folderPath := filepath.Dir(path)
				checker := f.ignoreCheckerPerFolder[folderPath]
				wg.Add(1)
				go func() {
					defer wg.Done()
					if !checker.MatchesPath(path) {
						resultsCh <- path
					}
				}()
			}

			return nil
		})

		wg.Wait()

		if err != nil {
			f.logger.Err(err).Msg("Error during filepath.WalkDir")
		}
	}()

	return resultsCh
}

func (f *fileFilter) collectGlobs(path string) []string {
	var globs []string
	if path != f.repoRoot {
		globs = append(globs, f.globsPerFolder[filepath.Dir(path)]...)
	} else {
		defaultGlobs := []string{"**/.git/**", "**/.svn/**", "**/.hg/**", "**/.bzr/**", "**/.DS_Store/**"}
		globs = append(globs, defaultGlobs...)
	}

	for _, ignoreFile := range f.ignoreFiles {
		ignoreFilePath := filepath.Join(path, ignoreFile)
		fileInfo, err := os.Stat(ignoreFilePath)
		fileFound := err == nil && !fileInfo.IsDir()
		if fileFound {
			var content []byte
			content, err = os.ReadFile(ignoreFilePath)
			if err != nil {
				f.logger.Err(err).Msg("Can't parse ignore file" + ignoreFilePath)
			}
			if filepath.Base(ignoreFilePath) == ".snyk" { // .snyk files are yaml files and should be parsed differently
				parsedRules, err := parseDotSnykFile(content, f.repoRoot)
				globs = append(globs, parsedRules...)
				if err != nil {
					f.logger.Err(err).Msg("Can't parse .snyk file")
				}
			} else { // .gitignore, .dcignore, etc. are just a list of ignore rules
				parsedRules := parseIgnoreFile(content, f.repoRoot)
				globs = append(globs, parsedRules...)
			}
		}
	}
	return globs
}

func parseDotSnykFile(content []byte, baseDir string) ([]string, error) {
	type DotSnykRules struct {
		Exclude struct {
			Code   []string `yaml:"code"`
			Global []string `yaml:"global"`
		} `yaml:"exclude"`
	}

	var rules DotSnykRules
	err := yaml.Unmarshal(content, &rules)
	if err != nil {
		return nil, err
	}

	var globs []string
	for _, codeRule := range rules.Exclude.Code {
		globs = append(globs, parseIgnoreRuleToGlobs(codeRule, baseDir)...)
	}
	for _, codeRule := range rules.Exclude.Global {
		globs = append(globs, parseIgnoreRuleToGlobs(codeRule, baseDir)...)
	}

	return globs, nil
}

func parseIgnoreFile(content []byte, baseDir string) (ignores []string) {
	ignores = []string{}
	lines := strings.Split(string(content), "\n")

	for _, line := range lines {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		globs := parseIgnoreRuleToGlobs(line, baseDir)
		ignores = append(ignores, globs...)
	}
	return ignores
}

func parseIgnoreRuleToGlobs(rule string, baseDir string) (globs []string) {
	// Shamelessly stolen from code-client: https://github.com/snyk/code-client/blob/7a9e5cdbed4e8a6a0f2597fcd64b67800279e585/src/files.ts#L67

	// Mappings from .gitignore format to glob format:
	// `/foo/` => `/foo/**` (meaning: Ignore root (not sub) foo dir and its paths underneath.)
	// `/foo`	=> `/foo/**`, `/foo` (meaning: Ignore root (not sub) file and dir and its paths underneath.)
	// `foo/` => `**/foo/**` (meaning: Ignore (root/sub) foo dirs and their paths underneath.)
	// `foo` => `**/foo/**`, `foo` (meaning: Ignore (root/sub) foo files and dirs and their paths underneath.)
	prefix := ""
	const negation = "!"
	const slash = "/"
	const all = "**"
	baseDir = filepath.ToSlash(baseDir)

	if strings.HasPrefix(rule, negation) {
		rule = rule[1:]
		prefix = negation
	}
	startingSlash := strings.HasPrefix(rule, slash)
	startingGlobstar := strings.HasPrefix(rule, all)
	endingSlash := strings.HasSuffix(rule, slash)
	endingGlobstar := strings.HasSuffix(rule, all)

	if startingSlash || startingGlobstar {
		// case `/foo/`, `/foo` => `{baseDir}/foo/**`
		// case `**/foo/`, `**/foo` => `{baseDir}/**/foo/**`
		if !endingGlobstar {
			globs = append(globs, filepath.ToSlash(prefix+filepath.Join(baseDir, rule, all)))
		}
		// case `/foo` => `{baseDir}/foo`
		// case `**/foo` => `{baseDir}/**/foo`
		// case `/foo/**` => `{baseDir}/foo/**`
		// case `**/foo/**` => `{baseDir}/**/foo/**`
		if !endingSlash {
			globs = append(globs, filepath.ToSlash(prefix+filepath.Join(baseDir, rule)))
		}
	} else {
		// case `foo/`, `foo` => `{baseDir}/**/foo/**`
		if !endingGlobstar {
			globs = append(globs, filepath.ToSlash(prefix+filepath.Join(baseDir, all, rule, all)))
		}
		// case `foo` => `{baseDir}/**/foo`
		// case `foo/**` => `{baseDir}/**/foo/**`
		if !endingSlash {
			globs = append(globs, filepath.ToSlash(prefix+filepath.Join(baseDir, all, rule)))
		}
	}
	return globs
}
