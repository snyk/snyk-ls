package testutil

import (
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/lsp"
)

func NoopOutput(_ map[string][]lsp.Diagnostic, _ []hover.DocumentHovers) {}
