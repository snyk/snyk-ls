package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/sourcegraph/go-lsp"
)

type File struct {
	hash    string
	content string
}

type BackendService interface {
	createBundle(files map[lsp.DocumentURI]File) (string, []lsp.DocumentURI)
	extendBundle(files map[lsp.DocumentURI]File, removedFiles []lsp.DocumentURI) []lsp.DocumentURI
	retrieveDiagnostics() map[lsp.DocumentURI][]lsp.Diagnostic
}

type CodeBundleImpl struct {
	Backend         BackendService
	bundleHash      string
	bundleDocuments map[lsp.DocumentURI]File
	missingFiles    []lsp.DocumentURI
}

func hash(content string) string {
	bytes := sha256.Sum256([]byte(content))
	sum256 := hex.EncodeToString(bytes[:])
	return sum256
}

func (b *CodeBundleImpl) createBundleFromSource(files map[lsp.DocumentURI]lsp.TextDocumentItem) string {
	b.addToBundleDocuments(files)
	b.bundleHash, b.missingFiles = b.Backend.createBundle(b.bundleDocuments)
	return b.bundleHash
}

func (b *CodeBundleImpl) addToBundleDocuments(files map[lsp.DocumentURI]lsp.TextDocumentItem) {
	if b.bundleDocuments == nil {
		b.bundleDocuments = make(map[lsp.DocumentURI]File)
	}
	for uri, doc := range files {
		if (b.bundleDocuments[uri] == File{}) {
			b.bundleDocuments[uri] = File{
				hash:    hash(doc.Text),
				content: doc.Text,
			}
		}
	}
}

func (b *CodeBundleImpl) extendBundleFromSource(
	files map[lsp.DocumentURI]lsp.TextDocumentItem,
	removeFiles []lsp.DocumentURI,
) []lsp.DocumentURI {
	b.addToBundleDocuments(files)
	b.missingFiles = b.Backend.extendBundle(b.bundleDocuments, removeFiles)
	//b.removeFromBundleDocuments(removeFiles) //TODO test
	return b.missingFiles
}

func (b *CodeBundleImpl) DiagnosticData(registeredDocuments map[lsp.DocumentURI]lsp.TextDocumentItem) map[lsp.DocumentURI][]lsp.Diagnostic {
	if b.bundleHash == "" {
		b.bundleHash = b.createBundleFromSource(registeredDocuments)
	} else {
		//b.extendBundleFromSource(registeredDocuments, ) // TODO test: check for gaps and extend
	}

	diagnosticMap := b.Backend.retrieveDiagnostics()

	// only return requested diagnostics TODO test
	//for uri := range diagnosticMap {
	//	if (registeredDocuments[uri] == lsp.TextDocumentItem{}) {
	//		delete(diagnosticMap, uri)
	//	}
	//}

	return diagnosticMap
}

// TODO test
//func (b *CodeBundleImpl) removeFromBundleDocuments(files []lsp.DocumentURI) {
//	for f := range files {
//		delete(b.bundleDocuments, files[f])
//	}
//}
