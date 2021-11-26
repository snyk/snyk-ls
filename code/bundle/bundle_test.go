package bundle

import (
	"github.com/snyk/snyk-lsp/code"
	"github.com/snyk/snyk-lsp/code/structs"
	"github.com/snyk/snyk-lsp/util"
	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
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

	firstBundleFile = structs.File{
		Hash:    util.Hash(firstDoc.Text),
		Content: firstDoc.Text,
	}
)

func Test_createBundleFromSource_shouldReturnNonEmptyBundleHash(t *testing.T) {
	b := CodeBundleImpl{Backend: &code.FakeBackendService{}}
	b.bundleDocuments = map[lsp.DocumentURI]structs.File{}
	registeredDocuments := map[lsp.DocumentURI]lsp.TextDocumentItem{}
	registeredDocuments[firstDoc.URI] = firstDoc

	hash, _, _ := b.createBundleFromSource(registeredDocuments)
	assert.Equal(t, hash, b.bundleHash)
	assert.NotEqual(t, "", b.bundleHash)
}

func Test_createBundleFromSource_shouldAddDocumentToBundle(t *testing.T) {
	b := CodeBundleImpl{Backend: &code.FakeBackendService{BundleHash: "test-bundle-Hash"}}
	b.bundleDocuments = map[lsp.DocumentURI]structs.File{}
	registeredDocuments := map[lsp.DocumentURI]lsp.TextDocumentItem{}
	registeredDocuments[firstDoc.URI] = firstDoc

	bundleHash, _, _ := b.createBundleFromSource(registeredDocuments)

	assert.NotEqual(t, "", bundleHash)
	assert.NotEqual(t, structs.File{}, b.bundleDocuments[firstDoc.URI])
	assert.Equal(t, firstBundleFile, b.bundleDocuments[firstDoc.URI])
}

func Test_extendBundleFromSource_shouldAddDocumentToBundle(t *testing.T) {
	b := CodeBundleImpl{Backend: &code.FakeBackendService{BundleHash: "test-bundle-Hash"}}
	b.bundleHash = "test-Hash"
	b.bundleDocuments = map[lsp.DocumentURI]structs.File{}
	b.bundleDocuments[firstDoc.URI] = firstBundleFile
	registeredDocuments := map[lsp.DocumentURI]lsp.TextDocumentItem{}
	registeredDocuments[secondDoc.URI] = secondDoc

	secondBundleFile := structs.File{
		Hash:    util.Hash(secondDoc.Text),
		Content: secondDoc.Text,
	}

	missingFiles, _ := b.extendBundleFromSource(registeredDocuments)
	assert.Empty(t, missingFiles)
	assert.Equal(t, secondBundleFile, b.bundleDocuments[secondDoc.URI])
}

func TestCodeBundleImpl_DiagnosticData_should_create_bundle_when_hash_empty(t *testing.T) {
	hash := "testHash"
	backendMock := &code.FakeBackendService{BundleHash: hash}
	b := CodeBundleImpl{Backend: backendMock}
	b.bundleHash = ""
	registeredDocuments := map[lsp.DocumentURI]lsp.TextDocumentItem{}
	registeredDocuments[firstDoc.URI] = firstDoc

	_, _ = b.DiagnosticData(registeredDocuments)

	assert.Equal(t, hash, b.bundleHash)
	assert.Equal(t, 0, len(b.missingFiles))

	// verify that create bundle has been called on backend service
	params := backendMock.GetCallParams(0, code.CreateBundleWithSourceOperation)
	assert.NotNil(t, params)
	assert.Equal(t, 1, len(params))
	files := params[0].(map[lsp.DocumentURI]structs.File)
	assert.Equal(t, files[firstDoc.URI].Content, firstDoc.Text)
}

func TestCodeBundleImpl_DiagnosticData_should_extend_bundle_when_hash_not_empty(t *testing.T) {
	hash := ""
	backendMock := &code.FakeBackendService{BundleHash: hash}
	b := CodeBundleImpl{Backend: backendMock}

	registeredDocuments := map[lsp.DocumentURI]lsp.TextDocumentItem{}
	registeredDocuments[firstDoc.URI] = firstDoc
	// create bundle with first doc
	_, _, _ = b.createBundleFromSource(registeredDocuments)

	// now add a doc
	registeredDocuments[secondDoc.URI] = secondDoc

	// execute
	_, _ = b.DiagnosticData(registeredDocuments)

	// the bundle hash should be the same
	assert.Equal(t, backendMock.BundleHash, b.bundleHash)
	// the bundle documents should have been updated
	assert.Equal(t, b.bundleDocuments[secondDoc.URI].Content, secondDoc.Text)

	// verify that extend bundle has been called on backend service with additional file
	params := backendMock.GetCallParams(0, code.ExtendBundleWithSourceOperation)
	assert.NotNil(t, params)
	assert.Equal(t, 3, len(params))
	assert.Equal(t, b.bundleHash, params[0])
	files := params[1].(map[lsp.DocumentURI]structs.File)
	assert.Equal(t, files[secondDoc.URI].Content, secondDoc.Text)
}

func TestCodeBundleImpl_DiagnosticData_should_retrieve_from_backend(t *testing.T) {
	backendMock := &code.FakeBackendService{}
	b := CodeBundleImpl{Backend: backendMock}
	code.FakeDiagnosticUri = firstDoc.URI

	registeredDocuments := map[lsp.DocumentURI]lsp.TextDocumentItem{}
	registeredDocuments[firstDoc.URI] = firstDoc

	// execute
	diagnosticMap, _ := b.DiagnosticData(registeredDocuments)

	assert.NotNil(t, diagnosticMap)
	diagnostics := diagnosticMap[firstDoc.URI]
	assert.NotNil(t, diagnostics)
	assert.Equal(t, 1, len(diagnostics))
	assert.True(t, reflect.DeepEqual(code.FakeDiagnostic, diagnostics[0]))

	// verify that extend bundle has been called on backend service with additional file
	params := backendMock.GetCallParams(0, code.RetrieveDiagnosticsOperation)
	assert.NotNil(t, params)
	assert.Equal(t, 3, len(params))
	assert.Equal(t, b.bundleHash, params[0])
	assert.Equal(t, 0, params[2])
}
