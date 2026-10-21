/*
 * © 2026 Snyk Limited
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

type goRangeFinder struct {
	path        types.FilePath
	fileContent []byte
	logger      *zerolog.Logger
}

func (g *goRangeFinder) find(introducingPackageName string, introducingVersion string) (*ast.Node, *ast.Tree) {
	lines := strings.Split(strings.ReplaceAll(string(g.fileContent), "\r", ""), "\n")
	longestModuleLine := -1
	longestModule := ""
	for i, line := range lines {
		module := g.moduleOfRequireLine(line)
		if !g.isPackageInModule(introducingPackageName, module) || len(module) <= len(longestModule) {
			continue
		}
		longestModuleLine, longestModule = i, module
	}
	if longestModuleLine < 0 {
		return nil, nil
	}

	line := lines[longestModuleLine]
	r := types.Range{
		Start: types.Position{Line: longestModuleLine, Character: strings.Index(line, longestModule)},
		End:   types.Position{Line: longestModuleLine, Character: len(strings.TrimRight(line, " \"',)"))},
	}
	g.logger.Debug().Str("package", introducingPackageName).
		Str("version", introducingVersion).
		Str("path", string(g.path)).
		Interface("range", r).Msg("found range")
	return &ast.Node{Line: r.Start.Line, StartChar: r.Start.Character, EndChar: r.End.Character}, nil
}

func (g *goRangeFinder) preferredPathIndex(paths [][]string) int {
	preferred := 0
	for i := 1; i < len(paths); i++ {
		if g.isCloserPath(paths[i], paths[preferred]) {
			preferred = i
		}
	}
	return preferred
}

func (g *goRangeFinder) isCloserPath(candidate []string, current []string) bool {
	if len(current) == 0 {
		return len(candidate) > 0
	}
	candidateOwnsPackage := g.directDependencyContainsPackage(candidate)
	if candidateOwnsPackage != g.directDependencyContainsPackage(current) {
		return candidateOwnsPackage
	}
	return len(candidate) < len(current)
}

func (g *goRangeFinder) directDependencyContainsPackage(path []string) bool {
	if len(path) < 2 {
		return false
	}
	return g.isPackageInModule(g.withoutVersion(path[len(path)-1]), g.withoutVersion(path[1]))
}

func (g *goRangeFinder) withoutVersion(packageWithVersion string) string {
	name, _, _ := strings.Cut(packageWithVersion, "@")
	return name
}

func (g *goRangeFinder) moduleOfRequireLine(line string) string {
	if isComment(line) {
		return ""
	}
	fields := strings.Fields(strings.TrimPrefix(strings.TrimSpace(line), "require "))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func (g *goRangeFinder) isPackageInModule(packageName string, module string) bool {
	return module != "" && (packageName == module || strings.HasPrefix(packageName, module+"/"))
}
