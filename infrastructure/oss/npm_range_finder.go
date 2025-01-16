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
	"fmt"
	"strings"

	"github.com/snyk/snyk-ls/ast"
	"github.com/snyk/snyk-ls/domain/snyk"
)

type NpmRangeFinder struct {
	uri         string
	fileContent []byte
	myRange     snyk.Range
}

func (n *NpmRangeFinder) find(introducingPackageName string, introducingVersion string) (*ast.Node, *ast.Tree) {
	var lines = strings.Split(strings.ReplaceAll(string(n.fileContent), "\r\n", "\n"), "\n")

	node := ast.Node{}

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		elems := strings.Split(line, ":")
		if len(elems) > 1 {
			jsonKey := strings.Trim(strings.Trim(elems[0], " "), "\"")
			if jsonKey == introducingPackageName {
				node.Line = i
				node.StartChar = strings.Index(line, introducingVersion) - 1
				node.EndChar = len(strings.ReplaceAll(line, ",", ""))
				break
			}
		}
	}

	return &node, nil
}

func introducingPackageAndVersion(issue ossIssue) (string, string) {
	var packageName string
	var version string
	if len(issue.From) > 1 {
		split := strings.Split(issue.From[1], "@")
		splitArrayLength := len(split)
		packageSplit := split[splitArrayLength-2]
		if splitArrayLength > 2 {
			// handle scoped packages
			packageSplit = fmt.Sprintf("@%s", split[splitArrayLength-2])
		}
		switch issue.PackageManager {
		case "maven":
			index := strings.LastIndex(packageSplit, ":")
			packageName = packageSplit[index+1:]
		default:
			packageName = packageSplit
		}
		version = split[splitArrayLength-1]
	} else {
		packageName = issue.Name
		version = issue.Version
	}
	return packageName, version
}
