package oss

import (
	"github.com/rs/zerolog/log"
	"github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/ast/maven"
)

type MavenRangeFinder struct {
	doc lsp.TextDocumentItem
}

func (m MavenRangeFinder) Find(issue ossIssue) lsp.Range {
	searchPackage, version := introducingPackageAndVersion(issue)
	log.Debug().Interface("issue", issue).Str("searchPackage", searchPackage).Str("searchVersion", version)
	parser := maven.Parser{}
	tree := parser.Parse(m.doc.Text, m.doc.URI)
	for _, depNode := range tree.Root.Children {
		if searchPackage == depNode.Name {
			log.Debug().Interface("dependency", depNode).Str("issueId", issue.Id).Msg("Found dependency for issue")
			return lsp.Range{
				Start: lsp.Position{Line: depNode.Line, Character: depNode.StartChar},
				End:   lsp.Position{Line: depNode.Line, Character: depNode.EndChar},
			}
		}
	}
	return lsp.Range{}
}
