package filefilter

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
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
	repoRoot       string
	ignoreFiles    []string
	globsPerFolder map[string][]string
	logger         zerolog.Logger
}

func newFileFilter(rootFolder string) *fileFilter {
	return &fileFilter{
		repoRoot:       rootFolder,
		ignoreFiles:    []string{".gitignore", ".dcignore", ".snyk"},
		globsPerFolder: make(map[string][]string),
		logger:         log.With().Str("component", "fileFilter").Str("repoRoot", rootFolder).Logger(),
	}
}

func (f *fileFilter) findNonIgnoredFiles() <-chan string {
	resultsCh := make(chan string)
	filesPerFolder := make(map[string][]string)
	go func() {
		defer close(resultsCh)

		err := filepath.WalkDir(f.repoRoot, f.filepathWalker(filesPerFolder))

		if err != nil {
			f.logger.Err(err).Msg("Error during filepath.WalkDir")
		}

		var wg sync.WaitGroup

		// When a folder is scanned, a memory-heavy IgnoreParser object is created.
		// The number of concurrent folders being scanned is limited to prevent high memory peaks.
		// NumCPU is used as a reasonable default (instead of hardcoding a magic number),
		// even though the files inside the folders are also scanned concurrently.
		concurrentFolders := runtime.NumCPU()
		semaphore := make(chan struct{}, concurrentFolders)

		for folderPath, globs := range f.globsPerFolder {
			wg.Add(1)
			filesInFolder := filesPerFolder[folderPath]
			go func(globs []string) {
				defer wg.Done()
				semaphore <- struct{}{} // Acquire semaphore
				processFolder(filesInFolder, globs, resultsCh)
				<-semaphore // Release semaphore
			}(globs)
		}
		wg.Wait()

		if err != nil {
			f.logger.Err(err).Msg("Error during filepath.WalkDir")
		}
	}()

	return resultsCh
}

// processFolder processes a folder and sends the non-ignored files to the results channel.
// The function blocks until all files are processed.
func processFolder(files, globs []string, results chan<- string) {
	checker := ignore.CompileIgnoreLines(globs...)
	var wg sync.WaitGroup
	for _, file := range files {
		wg.Add(1)
		go func(file string) {
			defer wg.Done()
			if !checker.MatchesPath(file) {
				results <- file
			}
		}(file)
	}
	wg.Wait()
}

func (f *fileFilter) filepathWalker(filesPerFolder map[string][]string) fs.WalkDirFunc {
	return func(path string, dirEntry os.DirEntry, err error) error {
		if err != nil {
			f.logger.Err(err).Msg("Error during file traversal of directory \"" + path + "\"\n" +
				"Skipping Directory")
			return filepath.SkipDir
		}
		if dirEntry == nil {
			return nil
		}

		if dirEntry.IsDir() {
			globs := f.collectGlobs(path)
			f.globsPerFolder[path] = globs
		} else {
			folderPath := filepath.Dir(path)
			filesPerFolder[folderPath] = append(filesPerFolder[folderPath], path)
		}

		return nil
	}
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
