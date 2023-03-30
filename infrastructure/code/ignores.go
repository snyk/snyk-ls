package code

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v3"
)

func (sc *Scanner) loadIgnorePatternsAndCountFiles(folderPath string) (fileCount int, err error) {
	ignoreFiles := []string{".gitignore", ".dcignore", ".snyk"}
	ignores := getDefaultIgnorePatterns()
	log.Debug().
		Str("method", "loadIgnorePatternsAndCountFiles").
		Str("workspace", folderPath).
		Msg("searching for ignore files")
	err = filepath.WalkDir( // Count the files, and parse the ignore files
		folderPath, func(path string, dirEntry os.DirEntry, err error) error {
			fileCount++
			if err != nil {
				log.Debug().
					Str("method", "loadIgnorePatternsAndCountFiles - walker").
					Str("path", path).
					Err(err).
					Msg("error traversing files")
				return nil
			}
			if dirEntry == nil || dirEntry.IsDir() {
				return nil
			}

			if !slices.Contains(ignoreFiles, dirEntry.Name()) {
				return nil
			}

			log.Debug().Str("method", "loadIgnorePatternsAndCountFiles").Str("file", path).Msg("found ignore file")
			content, err := os.ReadFile(path)
			if err != nil {
				log.Err(err).Msg("Can't read" + path)
				return nil
			}

			baseDir := filepath.Dir(path)
			if dirEntry.Name() == ".snyk" { // .snyk is encoded in yaml, so we need to parse it differently
				globs, err := parseDotSnykFile(content, baseDir)
				if err != nil {
					log.Err(err).Msg("Can't parse .snyk file")
					return nil
				}

				ignores = append(ignores, globs...)
			} else {
				ignores = append(ignores, parseIgnoreFile(content, baseDir)...)
			}

			return nil
		},
	)

	if err != nil {
		return fileCount, err
	}

	sc.ignorePatterns = ignores
	log.Debug().Interface("ignorePatterns", ignores).Msg("Loaded and set ignore patterns")
	return fileCount, nil
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

func getDefaultIgnorePatterns() []string {
	var ignores = []string{"**/.git/**", "**/.svn/**", "**/.hg/**", "**/.bzr/**", "**/.DS_Store/**"}
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
