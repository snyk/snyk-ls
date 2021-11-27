package code

import (
	"github.com/sourcegraph/go-lsp"
)

type BackendService interface {
	CreateBundle(files map[lsp.DocumentURI]File) (string, []lsp.DocumentURI, error)
	ExtendBundle(bundleHash string, files map[lsp.DocumentURI]File, removedFiles []lsp.DocumentURI) ([]lsp.DocumentURI, error)
	RetrieveDiagnostics(bundleHash string, limitToFiles []lsp.DocumentURI, severity int) (map[lsp.DocumentURI][]lsp.Diagnostic, error)
}
