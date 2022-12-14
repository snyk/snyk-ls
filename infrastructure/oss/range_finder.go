/*
 * © 2022 Snyk Limited All rights reserved.
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
	"strings"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/domain/snyk"
)

type DefaultFinder struct {
	uri         sglsp.DocumentURI
	fileContent []byte
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
				Str("uri", string(f.uri)).
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
