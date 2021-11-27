package code

import (
	"github.com/snyk/snyk-lsp/util"
	"github.com/sourcegraph/go-lsp"
	"time"
)

type CodeBundleImpl struct {
	Backend         BackendService
	bundleHash      string
	bundleDocuments map[lsp.DocumentURI]File
	missingFiles    []lsp.DocumentURI
}

type SnykAnalysisTimeoutError struct {
	msg string
}

func (e SnykAnalysisTimeoutError) Error() string {
	return e.msg
}

func (b *CodeBundleImpl) createBundleFromSource(files map[lsp.DocumentURI]lsp.TextDocumentItem) (string, []lsp.DocumentURI, error) {
	b.addToBundleDocuments(files)
	var err error
	b.bundleHash, b.missingFiles, err = b.Backend.CreateBundle(b.bundleDocuments)
	return b.bundleHash, b.missingFiles, err
}

func (b *CodeBundleImpl) addToBundleDocuments(files map[lsp.DocumentURI]lsp.TextDocumentItem) {
	if b.bundleDocuments == nil {
		b.bundleDocuments = make(map[lsp.DocumentURI]File)
	}
	for uri, doc := range files {
		if (b.bundleDocuments[uri] == File{}) {
			b.bundleDocuments[uri] = File{
				Hash:    util.Hash(doc.Text),
				Content: doc.Text,
			}
		}
	}
}

func (b *CodeBundleImpl) extendBundleFromSource(files map[lsp.DocumentURI]lsp.TextDocumentItem) ([]lsp.DocumentURI, error) {
	var err error
	b.addToBundleDocuments(files)
	var removeFiles []lsp.DocumentURI
	// todo determine which files to change
	b.missingFiles, err = b.Backend.ExtendBundle(b.bundleHash, b.bundleDocuments, removeFiles)
	return b.missingFiles, err
}

func (b *CodeBundleImpl) DiagnosticData(registeredDocuments map[lsp.DocumentURI]lsp.TextDocumentItem) (map[lsp.DocumentURI][]lsp.Diagnostic, error) {
	var err error
	if b.bundleHash == "" {
		// we don't have missing files, as we're creating from source
		b.bundleHash, _, err = b.createBundleFromSource(registeredDocuments)
		if err != nil {
			return nil, err
		}
	} else {
		// we don't have missing files, as we're creating from source
		_, err := b.extendBundleFromSource(registeredDocuments)
		if err != nil {
			return nil, err
		}
	}
	for {
		start := time.Now()
		data, err := b.Backend.RetrieveDiagnostics(b.bundleHash, []lsp.DocumentURI{}, 0)
		if err != nil {
			return nil, err
		}
		if data != nil {
			return data, err
		}
		if time.Now().Sub(start) > 30*time.Second {
			return nil, SnykAnalysisTimeoutError{msg: "Analysis Call Timed out."}
		}
	}
}
