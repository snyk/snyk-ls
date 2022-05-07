package oss

import (
	"context"

	"github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/ast/maven"
)

type MavenRangeFinder struct {
	uri         lsp.DocumentURI
	fileContent []byte
}

func (m *MavenRangeFinder) Find(ctx context.Context, issue ossIssue) lsp.Range {
	searchPackage, version := introducingPackageAndVersion(ctx, issue)
	logger.
		WithField("method", "MavenRangeFinder.Find").
		WithField("searchPackage", searchPackage).
		WithField("searchVersion", version).
		Trace(ctx, "searching...")
	parser := maven.Parser{}
	tree := parser.Parse(ctx, string(m.fileContent), m.uri)
	for _, depNode := range tree.Root.Children {
		if searchPackage == depNode.Name {
			logger.
				WithField("method", "MavenRangeFinder.Find").
				WithField("dependency", depNode).
				WithField("issueId", issue.Id).
				Trace(ctx, "Found dependency for issue")
			return lsp.Range{
				Start: lsp.Position{Line: depNode.Line, Character: depNode.StartChar},
				End:   lsp.Position{Line: depNode.Line, Character: depNode.EndChar},
			}
		}
	}
	return lsp.Range{}
}
