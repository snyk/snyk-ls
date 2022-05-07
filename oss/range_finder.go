package oss

import (
	"context"
	"strings"

	sglsp "github.com/sourcegraph/go-lsp"
)

type RangeFinder interface {
	Find(ctx context.Context, issue ossIssue) sglsp.Range
}

type DefaultFinder struct {
	uri         sglsp.DocumentURI
	fileContent []byte
}

func (f *DefaultFinder) Find(ctx context.Context, issue ossIssue) sglsp.Range {
	searchPackage, version := introducingPackageAndVersion(ctx, issue)
	lines := strings.Split(strings.ReplaceAll(string(f.fileContent), "\r", ""), "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		if strings.Contains(line, searchPackage) {
			endChar := len(strings.TrimRight(strings.TrimRight(strings.TrimRight(line, " "), "\""), "'"))
			r := sglsp.Range{
				Start: sglsp.Position{Line: i, Character: strings.Index(line, searchPackage)},
				End:   sglsp.Position{Line: i, Character: endChar},
			}
			logger.
				WithField("method", "DefaultFinder.Find").
				WithField("searchPackage", searchPackage).
				WithField("searchVersion", version).
				WithField("issueId", issue.Id).
				WithField("uri", string(f.uri)).
				WithField("range", r).
				Trace(ctx, "found range")
			return r
		}
	}
	return sglsp.Range{}
}

func isComment(line string) bool {
	return strings.HasPrefix(strings.Trim(line, " "), "//") ||
		strings.HasPrefix(strings.Trim(line, " "), "#")
}
