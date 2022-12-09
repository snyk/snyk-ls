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
	"github.com/rs/zerolog/log"
	"github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/ast/maven"
	"github.com/snyk/snyk-ls/domain/snyk"
)

type mavenRangeFinder struct {
	uri         lsp.DocumentURI //todo remove lsp dependency
	fileContent []byte
}

func (m *mavenRangeFinder) find(issue ossIssue) snyk.Range {
	searchPackage, version := introducingPackageAndVersion(issue)
	log.Trace().Interface("issue", issue).Str("searchPackage", searchPackage).Str("searchVersion", version)
	parser := maven.Parser{}
	tree := parser.Parse(string(m.fileContent), m.uri)
	for _, depNode := range tree.Root.Children {
		if searchPackage == depNode.Name {
			log.Trace().Interface("dependency", depNode).Str("issueId", issue.Id).Msg("Found dependency for issue")
			return snyk.Range{
				Start: snyk.Position{Line: depNode.Line, Character: depNode.StartChar},
				End:   snyk.Position{Line: depNode.Line, Character: depNode.EndChar},
			}
		}
	}
	return snyk.Range{}
}
