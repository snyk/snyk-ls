package interfaces

import (
	"github.com/snyk/snyk-lsp/code/structs"
	"github.com/sourcegraph/go-lsp"
)

type BackendService interface {
	CreateBundle(files map[lsp.DocumentURI]structs.File) (string, []lsp.DocumentURI, error)
	ExtendBundle(bundleHash string, files map[lsp.DocumentURI]structs.File, removedFiles []lsp.DocumentURI) ([]lsp.DocumentURI, error)
	RetrieveDiagnostics(bundleHash string, limitToFiles []lsp.DocumentURI, severity int) (map[lsp.DocumentURI][]lsp.Diagnostic, error)
}
