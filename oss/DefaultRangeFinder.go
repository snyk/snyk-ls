package oss

import (
	"strings"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"
)

type DefaultFinder struct {
	doc sglsp.TextDocumentItem
}

func (f *DefaultFinder) Find(issue ossIssue) sglsp.Range {
	searchPackage, version := introducingPackageAndVersion(issue)
	lines := strings.Split(strings.ReplaceAll(f.doc.Text, "\r", ""), "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		if strings.Contains(line, searchPackage) {
			r := sglsp.Range{
				Start: sglsp.Position{Line: i, Character: strings.Index(line, searchPackage)},
				End:   sglsp.Position{Line: i, Character: len(line)},
			}
			log.Debug().Str("package", searchPackage).
				Str("version", version).
				Str("issueId", issue.Id).
				Str("uri", string(f.doc.URI)).
				Interface("range", r).Msg("found range")
			return r
		}
	}
	return sglsp.Range{}
}

func isComment(line string) bool {
	return strings.HasPrefix(strings.Trim(line, " "), "//") ||
		strings.HasPrefix(strings.Trim(line, " "), "#")
}
