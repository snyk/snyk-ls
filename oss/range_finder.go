package oss

import (
	"strings"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"
)

type DefaultFinder struct {
	uri         sglsp.DocumentURI
	fileContent []byte
}

func (f *DefaultFinder) Find(issue ossIssue) sglsp.Range {
	searchPackage, version := introducingPackageAndVersion(issue)
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
			log.Debug().Str("package", searchPackage).
				Str("version", version).
				Str("issueId", issue.Id).
				Str("uri", string(f.uri)).
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
