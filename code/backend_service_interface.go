package code

import (
	"github.com/snyk/snyk-lsp/lsp"
	sglsp "github.com/sourcegraph/go-lsp"
)

type BackendService interface {
	CreateBundle(files map[sglsp.DocumentURI]File) (string, []sglsp.DocumentURI, error)
	ExtendBundle(bundleHash string, files map[sglsp.DocumentURI]File, removedFiles []sglsp.DocumentURI) ([]sglsp.DocumentURI, error)
	RetrieveDiagnostics(bundleHash string, limitToFiles []sglsp.DocumentURI, severity int) (map[sglsp.DocumentURI][]lsp.Diagnostic, error)
}
