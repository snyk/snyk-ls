package filefilter

import (
	"encoding/json"
	"hash/fnv"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/puzpuzpuz/xsync"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	ignore "github.com/sabhiram/go-gitignore"
	"gopkg.in/yaml.v3"

	"github.com/snyk/snyk-ls/internal/util"
)

const defaultParallelism = 4

// parallelism is the number of concurrent goroutines that can be used to check if a file is ignored.
// It is set to the defaultParallelism, unless there are fewer CPU cores.
// For safety, it is set to be at least 1.
var parallelism = util.Max(1, util.Min(defaultParallelism, runtime.NumCPU()))

// semaphore is used to limit the number of concurrent CPU-heavy ignore checks.
// It is global because there can be several file filters running concurrently on the same machine.
var semaphore = make(chan struct{}, parallelism)

func FindNonIgnoredFiles(rootFolder string) <-chan string {
	return NewFileFilter(rootFolder).FindNonIgnoredFiles()
}

type FileFilter struct {
	// The path to the root of the repository
	repoRoot       string
	ignoreFiles    []string
	globsPerFolder map[string][]string
	logger         zerolog.Logger
	cache          *xsync.MapOf[string, cachedResults]
}

type cachedResults struct {
	Hash    uint64
	Results []string
}

func hashFolder(globs, files []string) (uint64, error) {
	data := struct {
		Files []string
		Globs []string
	}{
		Files: files,
		Globs: globs,
	}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return 0, err
	}

	h := fnv.New64a()
	_, err = h.Write(dataBytes)
	if err != nil {
		return 0, err
	}
	hash := h.Sum64()

	return hash, nil
}

func NewFileFilter(rootFolder string) *FileFilter {
	return &FileFilter{
		repoRoot:       rootFolder,
		ignoreFiles:    []string{".gitignore", ".dcignore", ".snyk"},
		globsPerFolder: make(map[string][]string),
		logger:         log.With().Str("component", "FileFilter").Str("repoRoot", rootFolder).Logger(),
		cache:          xsync.NewMapOf[cachedResults](),
	}
}

func (f *FileFilter) FindNonIgnoredFiles() <-chan string {
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
		concurrentFolders := parallelism
		folderSemaphore := make(chan struct{}, concurrentFolders)

		for folderPath, globs := range f.globsPerFolder {
			wg.Add(1)
			filesInFolder := filesPerFolder[folderPath]
			go func(globs []string, folderPath string) {
				defer wg.Done()
				folderSemaphore <- struct{}{} // Acquire folderSemaphore
				f.processFolder(folderPath, filesInFolder, globs, resultsCh)
				<-folderSemaphore // Release folderSemaphore
			}(globs, folderPath)
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
func (f *FileFilter) processFolder(folderPath string, files, globs []string, results chan<- string) {
	hashFailed := false
	hash, err := hashFolder(globs, files)
	if err != nil {
		f.logger.Err(err).Msg("Error during hash calculation")
		hashFailed = true
	} else {
		cacheEntry, found := f.cache.Load(folderPath)
		if found {
			if hash == cacheEntry.Hash {
				for _, file := range cacheEntry.Results {
					results <- file
				}
				return
			}
		}
	}

	checker := ignore.CompileIgnoreLines(globs...) // This is memory heavy
	var resultsLock sync.Mutex
	var resultsToCache []string
	var wg sync.WaitGroup
	for _, file := range files {
		wg.Add(1)
		go func(file string) {
			defer func() {
				wg.Done()
				<-semaphore // Release semaphore
			}()
			semaphore <- struct{}{} // Acquire semaphore
			if !checker.MatchesPath(file) {
				resultsLock.Lock()
				resultsToCache = append(resultsToCache, file)
				resultsLock.Unlock()
				results <- file
			}
		}(file)
	}
	wg.Wait()

	if !hashFailed {
		f.cache.Store(folderPath, cachedResults{
			Hash:    hash,
			Results: resultsToCache,
		})
	}
}

func (f *FileFilter) filepathWalker(filesPerFolder map[string][]string) fs.WalkDirFunc {
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

func (f *FileFilter) collectGlobs(path string) []string {
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
