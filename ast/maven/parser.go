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

package maven

import (
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/ast"
	"github.com/snyk/snyk-ls/internal/types"
)

type Parser struct {
	config *config.Config
}

type Parent struct {
	Group        string `xml:"group"`
	ArtifactId   string `xml:"artifactId"`
	Version      string `xml:"version"`
	RelativePath string `xml:"relativePath"`
}

type Dependency struct {
	Group      string `xml:"group"`
	ArtifactId string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Type       string `xml:"type"`
}

func New(c *config.Config) Parser {
	return Parser{
		config: c,
	}
}

func (p *Parser) Parse(content string, path types.FilePath) *ast.Tree {
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
			p.config.Logger().Err(err).Msg("Couldn't parse XML")
		}

		switch xmlType := token.(type) {
		case xml.StartElement:
			if xmlType.Name.Local == "dependency" {
				var dep Dependency
				if err = d.DecodeElement(&dep, &xmlType); err != nil {
					p.config.Logger().Err(err).Msg("Couldn't decode Dependency")
					continue
				}

				if strings.ToLower(dep.Type) == "bom" {
					addDepsFromBOM(path, tree, dep)
				}

				offsetAfter := d.InputOffset()
				node := p.addNewNodeTo(tree.Root, offset, offsetAfter, dep)
				p.config.Logger().Debug().Interface("nodeName", node.Name).Str("path", tree.Document).Msg("Added Dependency node")
			}
			if xmlType.Name.Local == "parent" {
				// parse Parent pom
				var parentPOM Parent
				if err = d.DecodeElement(&parentPOM, &xmlType); err != nil {
					p.config.Logger().Err(err).Msg("Couldn't decode Parent")
					continue
				}

				if parentPOM.RelativePath == "" {
					parentPOM.RelativePath = filepath.Join("..", "pom.xml")
				}

				parentAbsPath, err := filepath.Abs(filepath.Join(pomDir, parentPOM.RelativePath))
				if err != nil {
					p.config.Logger().Err(err).Msg("Couldn't resolve Parent path")
					continue
				}
				content, err := os.ReadFile(parentAbsPath)
				if err != nil {
					p.config.Logger().Err(err).Msg("Couldn't read Parent file")
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
		// highlight artifact, if version is not there (bom/parent pom)
		startTag = "<artifactId>"
		endTag = "</artifactId>"
	}

	startTagOffset := strings.LastIndex(contentInclusiveDep, startTag)
	contentToVersionStart := content[0:startTagOffset]
	line = strings.Count(contentToVersionStart, "\n")
	lineStartOffset := strings.LastIndex(contentToVersionStart, "\n") + 1
	startChar = startTagOffset + len(startTag) - lineStartOffset
	versionEndOffset := strings.LastIndex(contentInclusiveDep, endTag)
	endChar = versionEndOffset - lineStartOffset

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
