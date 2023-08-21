/*
 * © 2022-2023 Snyk Limited
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

package oss

import (
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
)

type RangeFinder interface {
	find(issue ossIssue) snyk.Range
}
type DefaultFinder struct {
	path        string
	fileContent []byte
}

func findRange(issue ossIssue, path string, fileContent []byte) snyk.Range {
	var foundRange snyk.Range
	var finder RangeFinder

	if len(fileContent) == 0 {
		return snyk.Range{Start: snyk.Position{}, End: snyk.Position{}}
	}

	switch issue.PackageManager {
	case "npm":
		if packageScanSupportedExtensions[filepath.Ext(path)] {
			finder = &htmlRangeFinder{path: path, fileContent: fileContent, config: config.CurrentConfig()}
		} else {
			finder = &NpmRangeFinder{uri: path, fileContent: fileContent}
		}
	case "maven":
		if strings.HasSuffix(path, "pom.xml") {
			finder = &mavenRangeFinder{path: path, fileContent: fileContent}
		} else {
			finder = &DefaultFinder{path: path, fileContent: fileContent}
		}
	default:
		finder = &DefaultFinder{path: path, fileContent: fileContent}
	}

	foundRange = finder.find(issue)
	return foundRange
}

func (f *DefaultFinder) find(issue ossIssue) snyk.Range {
	searchPackage, version := introducingPackageAndVersion(issue)
	lines := strings.Split(strings.ReplaceAll(string(f.fileContent), "\r", ""), "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		if strings.Contains(line, searchPackage) {
			endChar := len(strings.TrimRight(strings.TrimRight(strings.TrimRight(line, " "), "\""), "'"))
			r := snyk.Range{
				Start: snyk.Position{Line: i, Character: strings.Index(line, searchPackage)},
				End:   snyk.Position{Line: i, Character: endChar},
			}
			log.Debug().Str("package", searchPackage).
				Str("version", version).
				Str("issueId", issue.Id).
				Str("path", f.path).
				Interface("range", r).Msg("found range")
			return r
		}
	}
	return snyk.Range{}
}

func isComment(line string) bool {
	return strings.HasPrefix(strings.Trim(line, " "), "//") ||
		strings.HasPrefix(strings.Trim(line, " "), "#")
}
