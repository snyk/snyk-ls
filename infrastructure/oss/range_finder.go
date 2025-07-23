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
	"strings"

	"github.com/rs/zerolog"

	"github.com/snyk/snyk-ls/ast"
	"github.com/snyk/snyk-ls/internal/types"
)

type RangeFinder interface {
	find(introducingPackageName string, introducingVersion string) (*ast.Node, *ast.Tree)
}

type DefaultFinder struct {
	path        types.FilePath
	fileContent []byte
	logger      *zerolog.Logger
}

// getDependencyNode will return the dependency node with range information
// in case of maven, the node will also contain tree links information for the whole dep tree
func getDependencyNode(logger *zerolog.Logger, path types.FilePath, issue ossIssue, fileContent []byte) *ast.Node {
	var finder RangeFinder

	if len(fileContent) == 0 {
		return nil
	}

	pathAsString := string(path)
	switch issue.PackageManager {
	case "npm":
		finder = &NpmRangeFinder{uri: path, fileContent: fileContent}
	case "maven":
		if strings.HasSuffix(pathAsString, "pom.xml") {
			finder = &mavenRangeFinder{path: path, fileContent: fileContent, logger: logger}
		} else {
			finder = &DefaultFinder{path: path, fileContent: fileContent, logger: logger}
		}
	default:
		finder = &DefaultFinder{path: path, fileContent: fileContent, logger: logger}
	}

	introducingPackageName, introducingVersion := introducingPackageAndVersion(issue)

	currentDep, parsedTree := finder.find(introducingPackageName, introducingVersion)

	// if an intermediate manifest file does not have a dependency section
	// we go recurse to the parent of it
	if currentDep == nil && parsedTree != nil && parsedTree.ParentTree != nil {
		tree := parsedTree.ParentTree
		currentDep = getDependencyNode(logger, types.FilePath(tree.Document), issue, []byte(tree.Root.Value))
	}

	// recurse until a dependency with version was found
	if currentDep != nil && currentDep.Value == "" && currentDep.Tree != nil && currentDep.Tree.ParentTree != nil {
		tree := currentDep.Tree.ParentTree
		currentDep.LinkedParentDependencyNode = getDependencyNode(logger, types.FilePath(tree.Document), issue, []byte(tree.Root.Value))
	}

	return currentDep
}

func (f *DefaultFinder) find(introducingPackageName string, introducingVersion string) (*ast.Node, *ast.Tree) {
	lines := strings.Split(strings.ReplaceAll(string(f.fileContent), "\r", ""), "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		if strings.Contains(line, introducingPackageName) {
			// length of line is ignoring some trailing characters
			endChar := len(strings.TrimRight(line, " \"',)"))
			r := types.Range{
				Start: types.Position{Line: i, Character: strings.Index(line, introducingPackageName)},
				End:   types.Position{Line: i, Character: endChar},
			}
			f.logger.Debug().Str("package", introducingPackageName).
				Str("version", introducingVersion).
				Str("path", string(f.path)).
				Interface("range", r).Msg("found range")
			return &ast.Node{Line: r.Start.Line, StartChar: r.Start.Character, EndChar: r.End.Character}, nil
		}
	}
	return nil, nil
}

func isComment(line string) bool {
	return strings.HasPrefix(strings.Trim(line, " "), "//") ||
		strings.HasPrefix(strings.Trim(line, " "), "#")
}
