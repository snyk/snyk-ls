package deleteme

import (
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/lsp"
)

//todo this should be incorporated back into the domain once we use snyk domain rather that LSP + IDE (circular deps otherwise)
type ResultProcessor = func(diagnostics []lsp.Diagnostic, hovers []hover.DocumentHovers)

func NoopResultProcessor(_ []lsp.Diagnostic, _ []hover.DocumentHovers) {}
