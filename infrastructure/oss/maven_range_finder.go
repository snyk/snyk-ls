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
	"github.com/rs/zerolog"

	"github.com/snyk/snyk-ls/ast"
	"github.com/snyk/snyk-ls/ast/maven"
	"github.com/snyk/snyk-ls/internal/types"
)

type mavenRangeFinder struct {
	path        types.FilePath
	fileContent []byte
	logger      *zerolog.Logger
}

func (m *mavenRangeFinder) find(introducingPackageName string, introducingVersion string) (*ast.Node, *ast.Tree) {
	parser := maven.New(m.logger)
	tree := parser.Parse(string(m.fileContent), m.path)
	for _, depNode := range tree.Root.Children {
		if introducingPackageName == depNode.Name {
			// mark, where the dep is mentioned in the file, regardless of parent pom/bom
			return depNode, tree
		}
	}
	return nil, tree
}
