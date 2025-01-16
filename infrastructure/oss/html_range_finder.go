/*
 * © 2023 Snyk Limited
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
	"fmt"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/ast"
	"github.com/snyk/snyk-ls/infrastructure/oss/parser"
)

type htmlRangeFinder struct {
	path        string
	fileContent []byte
	config      *config.Config
}

func (h htmlRangeFinder) find(introducingPackageName string, introducingVersion string) (*ast.Node, *ast.Tree) {
	dependencyParser := parser.NewParser(h.config, h.path)
	dependencies, err := dependencyParser.Parse(h.path)
	if err != nil {
		return nil, nil
	}
	for _, dependency := range dependencies {
		format := "%s@%s"
		if fmt.Sprintf(format, dependency.ArtifactID, dependency.Version) == fmt.Sprintf(format, introducingPackageName, introducingVersion) {
			return &ast.Node{
				Line:      dependency.Range.Start.Line,
				StartChar: dependency.Range.Start.Character,
				EndChar:   dependency.Range.End.Character,
			}, nil
		}
	}
	return nil, nil
}

var _ RangeFinder = &htmlRangeFinder{}
