/*
 * © 2025 Snyk Limited
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

// Package dockerfile provides a parser for Dockerfile AST generation
package dockerfile

import (
	"regexp"
	"strings"

	"github.com/rs/zerolog"

	"github.com/snyk/snyk-ls/ast"
	"github.com/snyk/snyk-ls/internal/types"
)

type Parser struct {
	logger zerolog.Logger
}

var (
	// fromRegex matches FROM instructions in Dockerfile
	fromRegex = regexp.MustCompile(`(?i)^\s*FROM\s+([^\s]+)`)
)

func New(logger *zerolog.Logger) Parser {
	return Parser{
		logger: *logger,
	}
}

func (p *Parser) Parse(content []byte, uri string) *ast.Tree {
	tree := p.initTree(types.FilePath(uri), string(content))

	lines := strings.Split(strings.ReplaceAll(string(content), "\r", ""), "\n")
	for lineNum, line := range lines {
		matches := fromRegex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		baseImage := matches[1]
		// Skip scratch base image
		if baseImage == "scratch" {
			continue
		}

		node := p.addFromNode(tree.Root, lineNum, line, baseImage)
		p.logger.Debug().Interface("nodeName", node.Name).Str("path", tree.Document).Msg("Added FROM node")
	}

	return tree
}

func (p *Parser) initTree(path types.FilePath, content string) *ast.Tree {
	root := ast.Node{
		Line:      0,
		StartChar: 0,
		EndChar:   -1,
		DocOffset: 0,
		Parent:    nil,
		Children:  nil,
		Name:      string(path),
		Value:     content,
	}

	root.Tree = &ast.Tree{
		Root:     &root,
		Document: string(path),
	}
	return root.Tree
}

func (p *Parser) addFromNode(parent *ast.Node, lineNum int, line string, baseImage string) *ast.Node {
	// Find the position of the base image in the line
	fromIndex := strings.Index(strings.ToLower(line), "from")
	imageStart := fromIndex + 4 // "FROM" length
	for imageStart < len(line) && line[imageStart] == ' ' {
		imageStart++ // Skip whitespace
	}
	endChar := imageStart + len(baseImage)

	node := ast.Node{
		Line:       lineNum,
		StartChar:  imageStart,
		EndChar:    endChar,
		DocOffset:  int64(fromIndex),
		Parent:     parent,
		Children:   nil,
		Name:       "FROM",
		Value:      baseImage,
		Attributes: make(map[string]string),
		Tree:       parent.Tree,
	}

	parent.Add(&node)
	return &node
}
