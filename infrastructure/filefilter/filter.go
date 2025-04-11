package filefilter

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/puzpuzpuz/xsync"
	"github.com/rs/zerolog"
	ignore "github.com/sabhiram/go-gitignore"
	"gopkg.in/yaml.v3"

	"github.com/snyk/snyk-ls/internal/progress"
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

func FindNonIgnoredFiles(t *progress.Tracker, rootFolder string, logger *zerolog.Logger) <-chan string {
	return NewFileFilter(rootFolder, logger).FindNonIgnoredFiles(t)
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
	Hash                 uint64
	FilteredFiles        []string
	FilteredChildFolders []string
}

type folderContent struct {
	Files   []string
	Globs   []string
	Folders []string
}

func hashFolder(globs, files, folders []string) (uint64, error) {
	sort.Strings(files)
	sort.Strings(folders)
	data := folderContent{
		Files:   files,
		Globs:   globs,
		Folders: folders,
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

func NewFileFilter(rootFolder string, logger *zerolog.Logger) *FileFilter {
	return &FileFilter{
		repoRoot:       rootFolder,
		ignoreFiles:    []string{".gitignore", ".dcignore", ".snyk"},
		globsPerFolder: make(map[string][]string),
		logger:         logger.With().Str("component", "FileFilter").Str("repoRoot", rootFolder).Logger(),
		cache:          xsync.NewMapOf[cachedResults](),
	}
}

// FindNonIgnoredFiles returns a channel of non-ignored files in the repository.
// The channel is closed when all files have been processed.
func (f *FileFilter) FindNonIgnoredFiles(t *progress.Tracker) <-chan string {
	t.ReportWithMessage(1, "collecting files in "+f.repoRoot)
	resultsCh := make(chan string)
	go func() {
		defer close(resultsCh)
		defer t.ReportWithMessage(10, "collected files in "+f.repoRoot)
		err := f.processFolders(f.repoRoot, t, resultsCh)
		if err != nil {
			f.logger.Err(err).Msg("Error during filepath.WalkDir")
		}
	}()

	return resultsCh
}

// processFolders walks through the folder structure recursively and filters files and folders based on the ignore files.
// It attempts to return cached results if the folder structure hasn't changed.
func (f *FileFilter) processFolders(folderPath string, progressTracker *progress.Tracker, results chan<- string) error {
	if progressTracker.IsCanceled() {
		return errors.New("progress was canceled")
	}

	progressTracker.ReportWithMessage(10, fmt.Sprintf("collecting files in %s", folderPath))
	c, err := f.collectFolderFiles(folderPath)
	if err != nil {
		return err
	}
	files := c.Files
	globs := c.Globs
	childFolders := c.Folders

	// Attempt to retrieve cached results.
	hashFailed := false
	hash, err := hashFolder(globs, files, childFolders)
	if err != nil {
		f.logger.Err(err).Msg("Error during hash calculation")
		hashFailed = true
	} else {
		cacheEntry, found := f.cache.Load(folderPath)
		if found && hash == cacheEntry.Hash { // Cache hit - returning cached results
			for _, file := range cacheEntry.FilteredFiles {
				results <- file
			}
			for _, childFolder := range cacheEntry.FilteredChildFolders {
				err = f.processFolders(childFolder, progressTracker, results)
				if err != nil {
					return err
				}
			}

			return nil
		}
	}

	// If results were not cached, filter files and folders, and store the results in the cache.
	progressTracker.ReportWithMessage(10, fmt.Sprintf("filtering files in %s", folderPath))
	filteredFiles, filteredChildFolders := f.filterFilesInFolder(globs, files, childFolders, results)
	for _, child := range filteredChildFolders {
		// Only process child folders that are not ignored
		err = f.processFolders(child, progressTracker, results)
		if err != nil {
			return err
		}
	}

	if !hashFailed { // Only cache results when hash calculation was successful
		f.cache.Store(folderPath, cachedResults{
			Hash:                 hash,
			FilteredFiles:        filteredFiles,
			FilteredChildFolders: filteredChildFolders,
		})
	}

	return err
}

func (f *FileFilter) filterFilesInFolder(globs []string,
	files []string,
	childFolders []string,
	results chan<- string,
) (filteredFiles []string, filteredChildFolders []string) {
	ignoreParser := ignore.CompileIgnoreLines(globs...) // This is memory heavy
	var wg sync.WaitGroup
	var resultsLock sync.Mutex
	for _, file := range files {
		wg.Add(1)
		go func(file string) {
			defer func() {
				wg.Done()
				<-semaphore // Release semaphore
			}()
			semaphore <- struct{}{} // Acquire semaphore

			if !ignoreParser.MatchesPath(file) {
				resultsLock.Lock()
				filteredFiles = append(filteredFiles, file)
				resultsLock.Unlock()
				results <- file
			}
		}(file)
	}

	for _, childFolder := range childFolders {
		semaphore <- struct{}{} // Acquire semaphore
		if !ignoreParser.MatchesPath(childFolder) {
			filteredChildFolders = append(filteredChildFolders, childFolder)
		}
		<-semaphore // Release semaphore
	}

	wg.Wait()
	ignoreParser = nil // Does this have any effect?
	return filteredFiles, filteredChildFolders
}

// collectFolderFiles collects the top-level files and child folders of a folder, along with the ignore rules (globs).
func (f *FileFilter) collectFolderFiles(folderPath string) (folderContent, error) {
	var files []string
	var globs []string
	var childFolders []string

	// The first iteration of this callback is going to be called for the root folder,
	// followed by all the files and folders in it.
	// Only the top level files and folders are of interest, so we skip the rest.
	err := filepath.WalkDir(folderPath, func(path string, dirEntry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if dirEntry.IsDir() {
			if path != folderPath {
				// We don't need to recursively go through the child folders yet, because they might be ignored.
				// Returning SkipDir will skip the entire subtree of the current folder.
				childFolders = append(childFolders, path)
				return filepath.SkipDir
			}

			// If it's the root folder, collect the globs
			globs = f.collectGlobs(path)
			f.addGlobsPerFolder(path, globs)
			return nil
		} else { // If it's a file, collect its path
			files = append(files, path)
		}

		return nil
	})

	content := folderContent{
		Files:   files,
		Globs:   globs,
		Folders: childFolders,
	}

	return content, err
}

func (f *FileFilter) addGlobsPerFolder(path string, globs []string) {
	cleanedDirPath := filepath.Clean(path)
	f.globsPerFolder[cleanedDirPath] = globs
}

func (f *FileFilter) getGlobsPerFolder(path string) []string {
	cleanedDirPath := filepath.Clean(path)
	return f.globsPerFolder[cleanedDirPath]
}

func (f *FileFilter) collectGlobs(path string) []string {
	var globs []string
	folderPath := path
	if path != f.repoRoot {
		pathDir := filepath.Dir(path)
		globs = append(globs, f.getGlobsPerFolder(pathDir)...)
	} else {
		folderPath = f.repoRoot
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
				parsedRules, err := parseDotSnykFile(content, folderPath)
				globs = append(globs, parsedRules...)
				if err != nil {
					f.logger.Err(err).Msg("Can't parse .snyk file")
				}
			} else { // .gitignore, .dcignore, etc. are just a list of ignore rules
				parsedRules := parseIgnoreFile(content, folderPath)
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
