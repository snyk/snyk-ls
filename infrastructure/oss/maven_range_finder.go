package oss

import (
	"github.com/rs/zerolog/log"
	"github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/ast/maven"
	"github.com/snyk/snyk-ls/domain/snyk"
)

type mavenRangeFinder struct {
	uri         lsp.DocumentURI //todo remove lsp dependency
	fileContent []byte
}

func (m *mavenRangeFinder) find(issue ossIssue) snyk.Range {
	searchPackage, version := introducingPackageAndVersion(issue)
	log.Trace().Interface("issue", issue).Str("searchPackage", searchPackage).Str("searchVersion", version)
	parser := maven.Parser{}
	tree := parser.Parse(string(m.fileContent), m.uri)
	for _, depNode := range tree.Root.Children {
		if searchPackage == depNode.Name {
			log.Trace().Interface("dependency", depNode).Str("issueId", issue.Id).Msg("Found dependency for issue")
			return snyk.Range{
				Start: snyk.Position{Line: depNode.Line, Character: depNode.StartChar},
				End:   snyk.Position{Line: depNode.Line, Character: depNode.EndChar},
			}
		}
	}
	return snyk.Range{}
}
