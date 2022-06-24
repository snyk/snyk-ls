package snyk

import (
	"context"

	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace/deleteme"
	"github.com/snyk/snyk-ls/lsp"
)

type TestScanner struct {
	Calls       int
	Hovers      []hover.DocumentHovers
	Diagnostics []lsp.Diagnostic
}

func NewTestScanner() *TestScanner {
	return &TestScanner{
		Calls:       0,
		Hovers:      []hover.DocumentHovers{},
		Diagnostics: []lsp.Diagnostic{},
	}
}

func (s *TestScanner) Scan(
	ctx context.Context,
	path string,
	processResults deleteme.ResultProcessor,
	naughtyHack1 string,
	naughtyHack2 []string,
) {
	processResults(s.Diagnostics, s.Hovers)
	s.Calls++
}
