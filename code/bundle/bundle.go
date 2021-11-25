package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/sourcegraph/go-lsp"
)

var (
	bundleHash      = ""
	bundleDocuments = map[lsp.DocumentURI]File{}
)

type File struct {
	hash    string
	content string
}

func hash(content string) string {
	bytes := sha256.Sum256([]byte(content))
	sum256 := hex.EncodeToString(bytes[:])
	return sum256
}

func createBundleFromSource(files map[lsp.DocumentURI]lsp.TextDocumentItem) string {
	bundleHash = "bundle-id"

	addToBundleDocuments(files)

	// todo create bundle via api
	return bundleHash
}

func addToBundleDocuments(files map[lsp.DocumentURI]lsp.TextDocumentItem) {
	for uri, doc := range files {
		if (bundleDocuments[uri] == File{}) {
			bundleDocuments[uri] = File{
				hash:    hash(doc.Text),
				content: doc.Text,
			}
		}
	}
}

func extendBundleFromSource(files map[lsp.DocumentURI]lsp.TextDocumentItem) []lsp.DocumentURI {

	// todo call extend bundle api
	// todo get missing files from api
	addToBundleDocuments(files)
	var missingFiles []lsp.DocumentURI
	return missingFiles
}

func GetDiagnosticData(registeredDocuments map[lsp.DocumentURI]lsp.TextDocumentItem) map[lsp.DocumentURI][]lsp.Diagnostic {
	if bundleHash == "" {
		bundleHash = createBundleFromSource(registeredDocuments)
	} else {
		extendBundleFromSource(registeredDocuments)
	}

	// todo call analysis
	// todo convert analysis suggestion object
	diagnosticMap := make(map[lsp.DocumentURI][]lsp.Diagnostic)
	diagnosticMap[DummyUri()] = dummyDiagnostic()
	return diagnosticMap
}

func DummyUri() lsp.DocumentURI {
	return "/dummy.java"
}

func dummyDiagnostic() []lsp.Diagnostic {
	diagnostic := lsp.Diagnostic{
		Range: lsp.Range{
			Start: lsp.Position{
				Line:      2,
				Character: 5,
			},
			End: lsp.Position{
				Line:      2,
				Character: 7,
			},
		},
		Severity: 0,
		Code:     "123",
		Source:   "snyk code",
		Message:  "Dummy",
	}
	var diagnostics []lsp.Diagnostic
	diagnostics = append(diagnostics, diagnostic)
	return diagnostics
}
