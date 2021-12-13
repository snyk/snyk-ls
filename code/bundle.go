package code

import (
	"github.com/snyk/snyk-lsp/lsp"
	"github.com/snyk/snyk-lsp/util"
	sglsp "github.com/sourcegraph/go-lsp"
	"path/filepath"
	"time"
)

var (
	// TODO get via filters request
	// extensions":[".java",".aspx",".cs",".cls",".ejs",".es",".es6",".htm",".html",".js",".jsx",".ts",".tsx",".vue",".py",".erb",".haml",".rb",".rhtml",".slim",".go",".c",".cc",".cpp",".cxx",".h",".hpp",".hxx",".php",".phtml"]
	extensions = map[string]bool{
		".java":  true,
		".aspx":  true,
		".cs":    true,
		".cls":   true,
		".ejs":   true,
		".es":    true,
		".es6":   true,
		".htm":   true,
		".html":  true,
		".js":    true,
		".jsx":   true,
		".ts":    true,
		".tsx":   true,
		".vue":   true,
		".py":    true,
		".erb":   true,
		".haml":  true,
		".rb":    true,
		".rhtml": true,
		".slim":  true,
		".go":    true,
		".c":     true,
		".cc":    true,
		".cpp":   true,
		".cxx":   true,
		".h":     true,
		".hpp":   true,
		".hxx":   true,
		".php":   true,
		".phtml": true,
	}
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
	if len(b.bundleDocuments) > 0 {
		b.bundleHash, b.missingFiles, err = b.Backend.CreateBundle(b.bundleDocuments)
	}
	return err
}

func (b *BundleImpl) addToBundleDocuments(files map[sglsp.DocumentURI]sglsp.TextDocumentItem) {
	if b.bundleDocuments == nil {
		b.bundleDocuments = make(map[sglsp.DocumentURI]File)
	}
	for uri, doc := range files {
		if extensions[filepath.Ext(string(uri))] {
			if (b.bundleDocuments[uri] == File{} && len(doc.Text) > 0) {
				b.bundleDocuments[uri] = File{
					Hash:    util.Hash(doc.Text),
					Content: doc.Text,
				}
			}
		}
	}
}

func (b *BundleImpl) extendBundleFromSource(files map[sglsp.DocumentURI]sglsp.TextDocumentItem) error {
	var err error
	b.addToBundleDocuments(files)
	var removeFiles []sglsp.DocumentURI
	// todo determine which files to change
	if len(b.bundleDocuments) > 0 {
		b.bundleHash, b.missingFiles, err = b.Backend.ExtendBundle(b.bundleHash, b.bundleDocuments, removeFiles)
	}
	return err
}

func (b *BundleImpl) DiagnosticData(
	registeredDocuments map[sglsp.DocumentURI]sglsp.TextDocumentItem,
) (
	map[sglsp.DocumentURI][]lsp.Diagnostic,
	map[sglsp.DocumentURI][]sglsp.CodeLens,
	error,
) {
	var err error

	if b.bundleHash == "" {
		// we don't have missing files, as we're creating from source
		err = b.createBundleFromSource(registeredDocuments)
		if err != nil {
			return nil, nil, err
		}
	} else {
		// we don't have missing files, as we're creating from source
		err := b.extendBundleFromSource(registeredDocuments)
		if err != nil {
			return nil, nil, err
		}
	}

	if len(b.bundleDocuments) > 0 {
		for {
			start := time.Now()
			diagnostics, codeLenses, status, err := b.Backend.RetrieveDiagnostics(b.bundleHash, []sglsp.DocumentURI{}, 0)
			if err != nil {
				return nil, nil, err
			}

			if diagnostics != nil {
				return diagnostics, codeLenses, err
			}

			if status == "COMPLETE" {
				return diagnostics, codeLenses, err
			}
			if time.Since(start) > 120*time.Second {
				return nil, nil, SnykAnalysisTimeoutError{msg: "Analysis Call Timed out."}
			}
			time.Sleep(1 * time.Second)
		}
	}
	return nil, nil, nil

}
