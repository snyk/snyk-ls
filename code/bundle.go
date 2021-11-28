package code

import (
	"github.com/snyk/snyk-lsp/lsp"
	"github.com/snyk/snyk-lsp/util"
	sglsp "github.com/sourcegraph/go-lsp"
	"time"
)

type BundleImpl struct {
	Backend         BackendService
	bundleHash      string
	bundleDocuments map[sglsp.DocumentURI]File
	missingFiles    []sglsp.DocumentURI
}

type SnykAnalysisTimeoutError struct {
	msg string
}

func (e SnykAnalysisTimeoutError) Error() string {
	return e.msg
}

func (b *BundleImpl) createBundleFromSource(files map[sglsp.DocumentURI]sglsp.TextDocumentItem) error {
	b.addToBundleDocuments(files)
	var err error
	b.bundleHash, b.missingFiles, err = b.Backend.CreateBundle(b.bundleDocuments)
	return err
}

func (b *BundleImpl) addToBundleDocuments(files map[sglsp.DocumentURI]sglsp.TextDocumentItem) {
	if b.bundleDocuments == nil {
		b.bundleDocuments = make(map[sglsp.DocumentURI]File)
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

func (b *BundleImpl) extendBundleFromSource(files map[sglsp.DocumentURI]sglsp.TextDocumentItem) error {
	var err error
	b.addToBundleDocuments(files)
	var removeFiles []sglsp.DocumentURI
	// todo determine which files to change
	b.bundleHash, b.missingFiles, err = b.Backend.ExtendBundle(b.bundleHash, b.bundleDocuments, removeFiles)
	return err
}

func (b *BundleImpl) DiagnosticData(registeredDocuments map[sglsp.DocumentURI]sglsp.TextDocumentItem) (map[sglsp.DocumentURI][]lsp.Diagnostic, error) {
	var err error

	if b.bundleHash == "" {
		// we don't have missing files, as we're creating from source
		err = b.createBundleFromSource(registeredDocuments)
		if err != nil {
			return nil, err
		}
	} else {
		// we don't have missing files, as we're creating from source
		err := b.extendBundleFromSource(registeredDocuments)
		if err != nil {
			return nil, err
		}
	}
	for {
		start := time.Now()
		data, status, err := b.Backend.RetrieveDiagnostics(b.bundleHash, []sglsp.DocumentURI{}, 0)
		if err != nil {
			return nil, err
		}

		if data != nil {
			return data, err
		}

		if status == "COMPLETE" {
			return data, nil
		}
		if time.Now().Sub(start) > 6*time.Second {
			return nil, SnykAnalysisTimeoutError{msg: "Analysis Call Timed out."}
		}
		time.Sleep(1 * time.Second)
	}

}
