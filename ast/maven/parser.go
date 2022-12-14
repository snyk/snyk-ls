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
	"io"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/ast"
)

type Parser struct {
	tree ast.Tree
}

type dependency struct {
	Group      string `xml:"group"`
	ArtifactId string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

func (p *Parser) Parse(content string, uri lsp.DocumentURI) ast.Tree {
	tree := p.initTree(uri, content)
	d := xml.NewDecoder(strings.NewReader(content))
	var offset int64
	for {
		token, err := d.Token()
		offset = d.InputOffset()
		if token == nil || err == io.EOF {
			// EOF means we're done.
			break
		} else if err != nil {
			log.Err(err).Msg("Couldn't parse XML")
		}

		switch xmlType := token.(type) {

		case xml.StartElement:
			if xmlType.Name.Local == "dependency" {
				var dep dependency
				if err = d.DecodeElement(&dep, &xmlType); err != nil {
					log.Err(err).Msg("Couldn't decode dependency")
				}
				offsetAfter := d.InputOffset()
				node := p.addNewNodeTo(tree.Root, offset, offsetAfter, dep)
				log.Debug().Interface("nodeName", node.Name).Str("uri", string(p.tree.Document)).Msg("Added dependency node")
			}
		default:
		}
	}
	return tree
}

func (p *Parser) initTree(uri lsp.DocumentURI, content string) ast.Tree {
	var currentLine = 0
	root := ast.Node{
		Line:      currentLine,
		StartChar: 0,
		EndChar:   -1,
		DocOffset: 0,
		Parent:    nil,
		Children:  nil,
		Name:      string(uri),
		Value:     content,
	}
	p.tree = ast.Tree{
		Root:     &root,
		Document: uri,
	}
	return p.tree
}

func (p *Parser) addNewNodeTo(parent *ast.Node, offsetBefore int64, offsetAfter int64, dep dependency) *ast.Node {
	content := p.tree.Root.Value
	contentInclusive := content[0:offsetAfter]
	startTag := "<version>"
	endTag := "</version"
	versionStartOffset := strings.LastIndex(contentInclusive, startTag)
	contentUntilVersion := content[0:versionStartOffset]
	line := strings.Count(contentUntilVersion, "\n")
	lineStartOffset := strings.LastIndex(contentUntilVersion, "\n")
	versionValueStartOffset := versionStartOffset + len(startTag) - lineStartOffset - 1
	versionValueEndOffset := strings.LastIndex(contentInclusive, endTag) - lineStartOffset - 1

	node := ast.Node{
		Line:       line,
		StartChar:  versionValueStartOffset,
		EndChar:    versionValueEndOffset,
		DocOffset:  offsetBefore,
		Parent:     parent,
		Children:   nil,
		Name:       dep.ArtifactId,
		Value:      dep.Version,
		Attributes: make(map[string]string),
	}
	parent.Add(&node)
	return &node
}
