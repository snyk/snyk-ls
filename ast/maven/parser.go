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

// maxParentDepth caps how deep the parent-POM chain is followed, as a backstop
// against pathological chains even when the visited-set has not yet caught a cycle.
const maxParentDepth = 32

// maxParentPOMSize bounds how many bytes we are willing to read for a single
// parent POM, guarding against a <relativePath> pointing at an unexpectedly large
// file. Real POMs are tiny; 16MiB is generous.
const maxParentPOMSize = 16 << 20

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
	return p.parse(content, path, map[string]bool{}, 0)
}

// parse is the recursive worker behind Parse. visited holds the absolute paths of
// POMs already parsed in this parent chain (cycle detection) and depth bounds the
// chain length (see maxParentDepth).
func (p *Parser) parse(content string, path types.FilePath, visited map[string]bool, depth int) *ast.Tree {
	content = strings.ReplaceAll(content, "\r", "")
	tree := p.initTree(path, content)
	if absPath, err := filepath.Abs(string(path)); err == nil {
		visited[absPath] = true
	}
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

		startElement, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		switch startElement.Name.Local {
		case "dependency":
			p.handleDependency(d, tree, path, &startElement, offset)
		case "properties":
			p.handleProperties(d, tree, content, &startElement, offset)
		case "parent":
			p.handleParent(d, tree, pomDir, &startElement, visited, depth)
		}
	}
	return tree
}

func (p *Parser) handleDependency(d *xml.Decoder, tree *ast.Tree, path types.FilePath, element *xml.StartElement, offset int64) {
	var dep Dependency
	if err := d.DecodeElement(&dep, element); err != nil {
		p.logger.Err(err).Msg("Couldn't decode Dependency")
		return
	}

	if strings.ToLower(dep.Type) == "bom" {
		addDepsFromBOM(path, tree, dep)
	}

	offsetAfter := d.InputOffset()
	node := p.addNewNodeTo(tree.Root, offset, offsetAfter, dep)
	p.logger.Debug().Interface("nodeName", node.Name).Str("path", tree.Document).Msg("Added Dependency node")
}

func (p *Parser) handleProperties(d *xml.Decoder, tree *ast.Tree, content string, element *xml.StartElement, offset int64) {
	// offset is the input position right after the <properties> start tag, i.e.
	// where the inner XML begins.
	var holder struct {
		Inner string `xml:",innerxml"`
	}
	if err := d.DecodeElement(&holder, element); err != nil {
		p.logger.Err(err).Msg("Couldn't decode properties")
		return
	}
	p.addPropertyNodes(tree, content, int(offset), holder.Inner)
}

func (p *Parser) handleParent(d *xml.Decoder, tree *ast.Tree, pomDir string, element *xml.StartElement, visited map[string]bool, depth int) {
	var parentPOM Parent
	if err := d.DecodeElement(&parentPOM, element); err != nil {
		p.logger.Err(err).Msg("Couldn't decode Parent")
		return
	}

	if parentPOM.RelativePath == "" {
		parentPOM.RelativePath = filepath.Join("..", "pom.xml")
	}

	parentAbsPath, err := filepath.Abs(filepath.Join(pomDir, parentPOM.RelativePath))
	if err != nil {
		p.logger.Err(err).Msg("Couldn't resolve Parent path")
		return
	}
	if depth+1 > maxParentDepth {
		p.logger.Warn().Str("path", parentAbsPath).Int("depth", depth).Msg("Maximum parent POM depth reached, skipping")
		return
	}
	if visited[parentAbsPath] {
		p.logger.Warn().Str("path", parentAbsPath).Msg("Cyclic parent POM reference detected, skipping")
		return
	}
	fi, err := os.Stat(parentAbsPath)
	if err != nil {
		p.logger.Err(err).Msg("Couldn't stat Parent file")
		return
	}
	if !fi.Mode().IsRegular() {
		p.logger.Warn().Str("path", parentAbsPath).Msg("Parent path is not a regular file, skipping")
		return
	}
	if fi.Size() > maxParentPOMSize {
		p.logger.Warn().Str("path", parentAbsPath).Int64("size", fi.Size()).Msg("Parent POM exceeds size limit, skipping")
		return
	}
	content, err := os.ReadFile(parentAbsPath)
	if err != nil {
		p.logger.Err(err).Msg("Couldn't read Parent file")
		return
	}
	tree.ParentTree = p.parse(string(content), types.FilePath(parentAbsPath), visited, depth+1)
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
		Root:       &root,
		Document:   string(path),
		Properties: map[string]*ast.Node{},
	}
	return root.Tree
}

// addPropertyNodes parses the children of a <properties> element and records a
// node per property in tree.Properties, with a range pointing at the property
// value. baseOffset is the absolute byte offset (in content) at which inner
// begins, so per-property offsets in inner can be mapped back to content.
func (p *Parser) addPropertyNodes(tree *ast.Tree, content string, baseOffset int, inner string) {
	dec := xml.NewDecoder(strings.NewReader(inner))
	for {
		token, err := dec.Token()
		if token == nil || errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			p.logger.Err(err).Msg("Couldn't parse properties")
			break
		}

		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}

		// The value spans from just after this start tag up to its end tag. Track
		// nesting depth so a property value that itself contains elements (e.g.
		// <v><x>1</x></v>) does not terminate the loop early at the first inner end
		// tag — only the property element's own closing tag (depth back to 0) ends
		// it. This also keeps the decoder positioned past the whole subtree so the
		// outer loop does not mistake a nested element for a top-level property.
		valueStartInInner := int(dec.InputOffset())
		valueEndInInner := valueStartInInner
		depth := 0
	valueLoop:
		for {
			inner, innerErr := dec.Token()
			if inner == nil || innerErr != nil {
				break
			}
			switch inner.(type) {
			case xml.StartElement:
				depth++
			case xml.EndElement:
				if depth == 0 {
					break valueLoop
				}
				depth--
			case xml.CharData:
				if depth == 0 {
					valueEndInInner = int(dec.InputOffset())
				}
			}
		}

		valueStartOffset := baseOffset + valueStartInInner
		valueEndOffset := baseOffset + valueEndInInner
		if valueStartOffset < 0 || valueStartOffset > valueEndOffset || valueEndOffset > len(content) {
			continue
		}

		rawValue := content[valueStartOffset:valueEndOffset]
		trimmedValue := strings.Trim(rawValue, " \t\n")
		if trimmedValue == "" {
			continue
		}
		leadingWhitespace := len(rawValue) - len(strings.TrimLeft(rawValue, " \t\n"))
		valueStartOffset += leadingWhitespace
		valueEndOffset = valueStartOffset + len(trimmedValue)

		tree.Properties[start.Name.Local] = newValueNode(tree, content, valueStartOffset, valueEndOffset, start.Name.Local, trimmedValue)
	}
}

// newValueNode builds an ast.Node whose range points at the value located at
// [valueStartOffset, valueEndOffset) within content.
func newValueNode(tree *ast.Tree, content string, valueStartOffset, valueEndOffset int, name, value string) *ast.Node {
	contentToValueStart := content[0:valueStartOffset]
	line := strings.Count(contentToValueStart, "\n")
	lineStartOffset := strings.LastIndex(contentToValueStart, "\n") + 1
	return &ast.Node{
		Line:       line,
		StartChar:  valueStartOffset - lineStartOffset,
		EndChar:    valueEndOffset - lineStartOffset,
		Name:       name,
		Value:      value,
		Attributes: make(map[string]string),
		Tree:       tree,
	}
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
