package code

import (
	"reflect"
	"sync"
	"testing"

	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	lsp2 "github.com/snyk/snyk-lsp/lsp"
	"github.com/snyk/snyk-lsp/util"
)

var (
	firstDoc = lsp.TextDocumentItem{
		URI:        "/test1.java",
		LanguageID: "java",
		Version:    0,
		Text:       "class1",
	}

	secondDoc = lsp.TextDocumentItem{
		URI:        "/test2.java",
		LanguageID: "java",
		Version:    3,
		Text:       "class2",
	}

	firstBundleFile = File{
		Hash:    util.Hash(firstDoc.Text),
		Content: firstDoc.Text,
	}
)

func Test_createBundleFromSource_shouldReturnNonEmptyBundleHash(t *testing.T) {
	b := BundleImpl{Backend: &FakeBackendService{}}
	b.bundleDocuments = map[lsp.DocumentURI]File{}
	registeredDocuments := map[lsp.DocumentURI]lsp.TextDocumentItem{}
	registeredDocuments[firstDoc.URI] = firstDoc

	_ = b.createBundleFromSource(registeredDocuments)
	assert.NotEqual(t, "", b.bundleHash)
}

func Test_createBundleFromSource_shouldAddDocumentToBundle(t *testing.T) {
	b := BundleImpl{Backend: &FakeBackendService{BundleHash: "test-bundle-Hash"}}
	b.bundleDocuments = map[lsp.DocumentURI]File{}
	registeredDocuments := map[lsp.DocumentURI]lsp.TextDocumentItem{}
	registeredDocuments[firstDoc.URI] = firstDoc

	_ = b.createBundleFromSource(registeredDocuments)

	assert.NotEqual(t, "", b.bundleHash)
	assert.NotEqual(t, File{}, b.bundleDocuments[firstDoc.URI])
	assert.Equal(t, firstBundleFile, b.bundleDocuments[firstDoc.URI])
}

func Test_extendBundleFromSource_shouldAddDocumentToBundle(t *testing.T) {
	b := BundleImpl{Backend: &FakeBackendService{BundleHash: "test-bundle-Hash"}}
	b.bundleHash = "test-Hash"
	b.bundleDocuments = map[lsp.DocumentURI]File{}
	b.bundleDocuments[firstDoc.URI] = firstBundleFile
	registeredDocuments := map[lsp.DocumentURI]lsp.TextDocumentItem{}
	registeredDocuments[secondDoc.URI] = secondDoc

	secondBundleFile := File{
		Hash:    util.Hash(secondDoc.Text),
		Content: secondDoc.Text,
	}

	_ = b.extendBundleFromSource(registeredDocuments)
	assert.Empty(t, b.missingFiles)
	assert.Equal(t, secondBundleFile, b.bundleDocuments[secondDoc.URI])
}

func TestCodeBundleImpl_DiagnosticData_should_create_bundle_when_hash_empty(t *testing.T) {
	hash := "testHash"
	backendMock := &FakeBackendService{BundleHash: hash}
	b := BundleImpl{Backend: backendMock}
	b.bundleHash = ""
	registeredDocuments := map[lsp.DocumentURI]lsp.TextDocumentItem{}
	registeredDocuments[firstDoc.URI] = firstDoc

	dChan := make(chan lsp2.DiagnosticResult)
	clChan := make(chan lsp2.CodeLensResult)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go b.DiagnosticData(registeredDocuments, &wg, dChan, clChan)

	<-dChan
	<-clChan

	assert.Equal(t, hash, b.bundleHash)
	assert.Equal(t, 0, len(b.missingFiles))

	// verify that create bundle has been called on backend service
	params := backendMock.GetCallParams(0, CreateBundleWithSourceOperation)
	assert.NotNil(t, params)
	assert.Equal(t, 1, len(params))
	files := params[0].(map[lsp.DocumentURI]File)
	assert.Equal(t, files[firstDoc.URI].Content, firstDoc.Text)
}

func TestCodeBundleImpl_DiagnosticData_should_extend_bundle_when_hash_not_empty(t *testing.T) {
	hash := "test"
	backendMock := &FakeBackendService{BundleHash: hash}
	b := BundleImpl{Backend: backendMock}

	registeredDocuments := map[lsp.DocumentURI]lsp.TextDocumentItem{}
	registeredDocuments[firstDoc.URI] = firstDoc
	// create bundle with first doc
	_ = b.createBundleFromSource(registeredDocuments)

	// now add a doc
	registeredDocuments[secondDoc.URI] = secondDoc

	// execute
	dChan := make(chan lsp2.DiagnosticResult)
	clChan := make(chan lsp2.CodeLensResult)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go b.DiagnosticData(registeredDocuments, &wg, dChan, clChan)

	<-dChan
	<-clChan

	// the bundle hash should be the same
	assert.Equal(t, backendMock.BundleHash, b.bundleHash)
	// the bundle documents should have been updated
	assert.Equal(t, b.bundleDocuments[secondDoc.URI].Content, secondDoc.Text)

	// verify that extend bundle has been called on backend service with additional file
	params := backendMock.GetCallParams(0, ExtendBundleWithSourceOperation)
	assert.NotNil(t, params)
	assert.Equal(t, 3, len(params))
	assert.Equal(t, b.bundleHash, params[0])
	files := params[1].(map[lsp.DocumentURI]File)
	assert.Equal(t, files[secondDoc.URI].Content, secondDoc.Text)
}

func TestCodeBundleImpl_DiagnosticData_should_retrieve_from_backend(t *testing.T) {
	backendMock := &FakeBackendService{}
	b := BundleImpl{Backend: backendMock}
	FakeDiagnosticUri = firstDoc.URI

	registeredDocuments := map[lsp.DocumentURI]lsp.TextDocumentItem{}
	registeredDocuments[firstDoc.URI] = firstDoc
	diagnosticMap := map[lsp.DocumentURI][]lsp2.Diagnostic{}

	// execute
	dChan := make(chan lsp2.DiagnosticResult)
	clChan := make(chan lsp2.CodeLensResult)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go b.DiagnosticData(registeredDocuments, &wg, dChan, clChan)
	result := <-dChan
	diagnosticMap[result.Uri] = result.Diagnostics
	<-clChan

	assert.NotNil(t, diagnosticMap)
	diagnostics := diagnosticMap[firstDoc.URI]
	assert.NotNil(t, diagnostics)
	assert.Equal(t, 1, len(diagnostics))
	assert.True(t, reflect.DeepEqual(FakeDiagnostic, diagnostics[0]))

	// verify that extend bundle has been called on backend service with additional file
	params := backendMock.GetCallParams(0, RetrieveDiagnosticsOperation)
	assert.NotNil(t, params)
	assert.Equal(t, 3, len(params))
	assert.Equal(t, b.bundleHash, params[0])
	assert.Equal(t, 0, params[2])
}

func TestCodeBundleImpl_DiagnosticData_should_return_code_lenses(t *testing.T) {
	backendMock := &FakeBackendService{}
	b := BundleImpl{Backend: backendMock}
	FakeDiagnosticUri = firstDoc.URI

	registeredDocuments := map[lsp.DocumentURI]lsp.TextDocumentItem{}
	registeredDocuments[firstDoc.URI] = firstDoc

	// execute
	dChan := make(chan lsp2.DiagnosticResult)
	clChan := make(chan lsp2.CodeLensResult)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go b.DiagnosticData(registeredDocuments, &wg, dChan, clChan)
	<-dChan

	codeLensMap := map[lsp.DocumentURI][]lsp.CodeLens{}
	result := <-clChan
	codeLensMap[result.Uri] = result.CodeLenses
	assert.NotEqual(t, 0, len(codeLensMap[firstDoc.URI]))
}
