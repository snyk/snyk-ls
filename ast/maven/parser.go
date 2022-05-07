package maven

import (
	"context"
	"encoding/xml"
	"io"
	"strings"

	"github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/ast"
	"github.com/snyk/snyk-ls/config/environment"
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

func (p *Parser) Parse(ctx context.Context, content string, uri lsp.DocumentURI) ast.Tree {
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
			environment.Logger.
				WithField("method", "Parse").
				WithError(err).
				Error(ctx, "couldn't parse code setting")
		}

		switch xmlType := token.(type) {

		case xml.StartElement:
			if xmlType.Name.Local == "dependency" {
				var dep dependency
				if err = d.DecodeElement(&dep, &xmlType); err != nil {
					environment.Logger.
						WithField("method", "Parse").
						WithField("uri", string(p.tree.Document)).
						Error(ctx, "couldn't decode dependency")
				}
				offsetAfter := d.InputOffset()
				node := p.addNewNodeTo(tree.Root, offset, offsetAfter, dep)
				environment.Logger.
					WithField("method", "Parse").
					WithField("nodeName", node.Name).
					WithField("uri", string(p.tree.Document)).
					Debug(ctx, "added dependency node")
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
