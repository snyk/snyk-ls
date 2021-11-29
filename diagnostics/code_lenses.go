package diagnostics

import sglsp "github.com/sourcegraph/go-lsp"

var codeLenseCache = map[sglsp.DocumentURI][]sglsp.CodeLens{}

func GetCodeLenses(uri sglsp.DocumentURI) ([]sglsp.CodeLens, error) {
	return codeLenseCache[uri], nil
}

func AddLens(uri sglsp.DocumentURI, lens sglsp.CodeLens) {
	// todo rewrite as set
	codeLenseCache[uri] = append(codeLenseCache[uri], lens)
}

func ClearLenses(uri sglsp.DocumentURI) {
	codeLenseCache[uri] = []sglsp.CodeLens{}
}
