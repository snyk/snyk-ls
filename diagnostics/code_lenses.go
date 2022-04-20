package diagnostics

import sglsp "github.com/sourcegraph/go-lsp"

var codeLenseCache = map[sglsp.DocumentURI][]sglsp.CodeLens{}

func GetCodeLenses(uri sglsp.DocumentURI) ([]sglsp.CodeLens, error) {
	return codeLenseCache[uri], nil
}

func AddLens(uri sglsp.DocumentURI, lens sglsp.CodeLens) {
	diagnosticsMutex.Lock()
	codeLenseCache[uri] = append(codeLenseCache[uri], lens)
	diagnosticsMutex.Unlock()
}

func ClearLenses(uri sglsp.DocumentURI) {
	diagnosticsMutex.Lock()
	codeLenseCache[uri] = []sglsp.CodeLens{}
	diagnosticsMutex.Unlock()
}
