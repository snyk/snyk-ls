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

// Package maven implements the Maven parser
package maven

import (
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog"

	"github.com/snyk/snyk-ls/ast"
	"github.com/snyk/snyk-ls/internal/types"
)

type Parser struct {
	logger *zerolog.Logger
}

type Parent struct {
	Group        string `xml:"groupId"`
	ArtifactId   string `xml:"artifactId"`
	Version      string `xml:"version"`
	RelativePath string `xml:"relativePath"`
}

type Dependency struct {
	Group      string `xml:"groupId"`
	ArtifactId string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Type       string `xml:"type"`
}

func New(logger *zerolog.Logger) Parser {
	return Parser{
		logger: logger,
	}
}

func (p *Parser) Parse(content string, path types.FilePath) *ast.Tree {
	content = strings.ReplaceAll(content, "\r", "")
	tree := p.initTree(path, content)
	d := xml.NewDecoder(strings.NewReader(content))
	var offset int64
	pomDir := filepath.Dir(string(path))
	for {
		token, err := d.Token()
		offset = d.InputOffset()
		if token == nil || errors.Is(err, io.EOF) {
			// EOF means we're done.
			break
		} else if err != nil {
			p.logger.Err(err).Msg("Couldn't parse XML")
		}

		switch xmlType := token.(type) {
		case xml.StartElement:
			if xmlType.Name.Local == "dependency" {
				var dep Dependency
				if err = d.DecodeElement(&dep, &xmlType); err != nil {
					p.logger.Err(err).Msg("Couldn't decode Dependency")
					continue
				}

				if strings.ToLower(dep.Type) == "bom" {
					addDepsFromBOM(path, tree, dep)
				}

				offsetAfter := d.InputOffset()
				node := p.addNewNodeTo(tree.Root, offset, offsetAfter, dep)
				p.logger.Debug().Interface("nodeName", node.Name).Str("path", tree.Document).Msg("Added Dependency node")
			}
			if xmlType.Name.Local == "parent" {
				// parse Parent pom
				var parentPOM Parent
				if err = d.DecodeElement(&parentPOM, &xmlType); err != nil {
					p.logger.Err(err).Msg("Couldn't decode Parent")
					continue
				}

				if parentPOM.RelativePath == "" {
					parentPOM.RelativePath = filepath.Join("..", "pom.xml")
				}

				parentAbsPath, err := filepath.Abs(filepath.Join(pomDir, parentPOM.RelativePath))
				if err != nil {
					p.logger.Err(err).Msg("Couldn't resolve Parent path")
					continue
				}
				content, err := os.ReadFile(parentAbsPath)
				if err != nil {
					p.logger.Err(err).Msg("Couldn't read Parent file")
					continue
				}
				parentTree := p.Parse(string(content), types.FilePath(parentAbsPath))
				tree.ParentTree = parentTree
			}
		default:
		}
	}
	return tree
}

func addDepsFromBOM(path types.FilePath, tree *ast.Tree, dep Dependency) {
	// todo retrieve, potentially from configured repos (not parsed yet)
}

func (p *Parser) initTree(path types.FilePath, content string) *ast.Tree {
	var currentLine = 0
	root := ast.Node{
		Line:      currentLine,
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

func (p *Parser) addNewNodeTo(parent *ast.Node, offsetBefore int64, offsetAfter int64, dep Dependency) *ast.Node {
	var startChar int
	var endChar int
	var line int
	content := parent.Tree.Root.Value
	contentInclusiveDep := content[0:offsetAfter]

	startTag := "<version>"
	endTag := "</version>"
	if dep.Version == "" {
		// highlight artifactId if version is not present (parent pom / dependencyManagement)
		startTag = "<artifactId>"
		endTag = "</artifactId>"
	}

	startTagOffset := strings.LastIndex(contentInclusiveDep, startTag)
	endTagOffset := strings.LastIndex(contentInclusiveDep, endTag)

	valueStartOffset := startTagOffset + len(startTag)
	valueEndOffset := endTagOffset
	if startTagOffset != -1 && endTagOffset != -1 && endTagOffset >= valueStartOffset {
		value := content[valueStartOffset:valueEndOffset]
		trimmedValue := strings.Trim(value, " \t\n")
		leadingWhitespace := len(value) - len(strings.TrimLeft(value, " \t\n"))
		valueStartOffset += leadingWhitespace
		valueEndOffset = valueStartOffset + len(trimmedValue)
	}

	contentToValueStart := content[0:valueStartOffset]
	line = strings.Count(contentToValueStart, "\n")
	lineStartOffset := strings.LastIndex(contentToValueStart, "\n") + 1
	startChar = valueStartOffset - lineStartOffset
	endChar = valueEndOffset - lineStartOffset

	node := ast.Node{
		Line:       line,
		StartChar:  startChar,
		EndChar:    endChar,
		DocOffset:  offsetBefore,
		Parent:     parent,
		Children:   nil,
		Name:       dep.ArtifactId,
		Value:      dep.Version,
		Attributes: make(map[string]string),
		Tree:       parent.Tree,
	}
	parent.Add(&node)
	return &node
}
