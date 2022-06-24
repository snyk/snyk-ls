package oss

import (
	"github.com/rs/zerolog/log"
	"github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/ast/maven"
)

type mavenRangeFinder struct {
	uri         lsp.DocumentURI
	fileContent []byte
}

func (m *mavenRangeFinder) find(issue ossIssue) lsp.Range {
	searchPackage, version := introducingPackageAndVersion(issue)
	log.Trace().Interface("issue", issue).Str("searchPackage", searchPackage).Str("searchVersion", version)
	parser := maven.Parser{}
	tree := parser.Parse(string(m.fileContent), m.uri)
	for _, depNode := range tree.Root.Children {
		if searchPackage == depNode.Name {
			log.Trace().Interface("dependency", depNode).Str("issueId", issue.Id).Msg("Found dependency for issue")
			return lsp.Range{
				Start: lsp.Position{Line: depNode.Line, Character: depNode.StartChar},
				End:   lsp.Position{Line: depNode.Line, Character: depNode.EndChar},
			}
		}
	}
	return lsp.Range{}
}
