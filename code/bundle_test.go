package code

import (
	"encoding/json"
	"reflect"
	"strconv"
	"sync"
	"testing"

	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	lsp2 "github.com/snyk/snyk-ls/lsp"
	"github.com/snyk/snyk-ls/util"
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
)

func Test_createBundleFromSource_shouldReturnNonEmptyBundleHash(t *testing.T) {
	b := BundleImpl{SnykCode: &FakeSnykCodeApiService{}}
	b.BundleDocuments = map[lsp.DocumentURI]File{}
	registeredDocuments := map[lsp.DocumentURI]lsp.TextDocumentItem{}
	registeredDocuments[firstDoc.URI] = firstDoc
	_ = b.AddToBundleDocuments(registeredDocuments)
	_ = b.createBundleFromSource()
	assert.NotEqual(t, "", b.BundleHash)
}

func Test_AddToBundleDocuments_shouldNotAddDocumentToBundleIfTooBig(t *testing.T) {
	b, registeredDocuments := setupBundleForTesting(128*1024 + 1)

	_ = b.AddToBundleDocuments(registeredDocuments)

	assert.Empty(t, b.missingFiles)
	assert.Empty(t, b.BundleDocuments)
}

func Test_AddToBundleDocuments_shouldNotAddDocumentToBundleIfEmpty(t *testing.T) {
	b, registeredDocuments := setupBundleForTesting(0)

	_ = b.AddToBundleDocuments(registeredDocuments)

	assert.Empty(t, b.missingFiles)
	assert.Empty(t, b.BundleDocuments)
}

func Test_AddToBundleDocuments_shouldReturnNotAddedFileIfBundleGreaterThanMaxPayloadSize(t *testing.T) {
	b, registeredDocuments := setupBundleForTesting(maxFileSize)
	for i := 0; i < (maxBundleSize / maxFileSize); i++ {
		uri := lsp.DocumentURI(strconv.Itoa(i) + ".java")
		registeredDocuments[uri] = lsp.TextDocumentItem{URI: uri, Text: registeredDocuments[secondDoc.URI].Text}
	}

	filesNotAdded := b.AddToBundleDocuments(registeredDocuments)

	assert.Len(t, filesNotAdded.Files, 2)
}

func Test_AddToBundleDocuments_shouldNotAddUnsupportedFileType(t *testing.T) {
	b, registeredDocuments := setupBundleForTesting(1) // this adds one file to bundle documents
	uri := lsp.DocumentURI("1")
	registeredDocuments[uri] = lsp.TextDocumentItem{URI: uri, Text: registeredDocuments[secondDoc.URI].Text}

	filesNotAdded := b.AddToBundleDocuments(registeredDocuments)

	assert.Len(t, filesNotAdded.Files, 0)
	assert.Len(t, b.BundleDocuments, 1)
}

func Test_getSize_shouldReturn0ForEmptyBundle(t *testing.T) {
	b, registeredDocuments := setupBundleForTesting(0)
	_ = b.AddToBundleDocuments(registeredDocuments)

	size := b.getSize()

	assert.Equal(t, 0, size)
}

func Test_getSize_shouldReturnTotalBundleSize(t *testing.T) {
	b, registeredDocuments := setupBundleForTesting(1)
	bundleDoc := lsp.TextDocumentItem{
		URI:  "file://hurz",
		Text: "test123",
	}
	registeredDocuments[bundleDoc.URI] = bundleDoc
	_ = b.AddToBundleDocuments(registeredDocuments)

	var req = extendBundleRequest{Files: b.BundleDocuments}
	bytes, err := json.Marshal(req)
	if err != nil {
		assert.Fail(t, err.Error(), "Couldn't marshal ", req)
	}

	size := b.getSize()

	assert.Equal(t, len(bytes), size)
}

func setupBundleForTesting(contentSize int) (BundleImpl, map[lsp.DocumentURI]lsp.TextDocumentItem) {
	b := BundleImpl{SnykCode: &FakeSnykCodeApiService{}}
	b.BundleHash = "test-Hash"
	b.BundleDocuments = map[lsp.DocumentURI]File{}
	registeredDocuments := map[lsp.DocumentURI]lsp.TextDocumentItem{}

	var fileContent string
	for i := 0; i < contentSize; i++ {
		fileContent += "a"
	}
	bundleDoc := secondDoc
	bundleDoc.Text = fileContent
	registeredDocuments[bundleDoc.URI] = bundleDoc
	return b, registeredDocuments
}

func TestCodeBundleImpl_FetchDiagnosticsData_shouldCreateBundleWhenHashEmpty(t *testing.T) {
	snykCodeMock := &FakeSnykCodeApiService{}
	b := BundleImpl{SnykCode: snykCodeMock}
	b.BundleHash = ""
	registeredDocuments := map[lsp.DocumentURI]lsp.TextDocumentItem{}
	registeredDocuments[firstDoc.URI] = firstDoc
	b.AddToBundleDocuments(registeredDocuments)

	dChan := make(chan lsp2.DiagnosticResult)
	clChan := make(chan lsp2.CodeLensResult)
	wg := sync.WaitGroup{}
	wg.Add(1)

	go b.FetchDiagnosticsData("", &wg, dChan, clChan)

	<-dChan
	<-clChan

	assert.Equal(t, 0, len(b.missingFiles))

	// verify that create bundle has been called on backend service
	params := snykCodeMock.GetCallParams(0, CreateBundleWithSourceOperation)
	assert.NotNil(t, params)
	assert.Equal(t, 1, len(params))
	files := params[0].(map[lsp.DocumentURI]File)
	assert.Equal(t, files[firstDoc.URI].Content, firstDoc.Text)
}

func TestCodeBundleImpl_FetchDiagnosticsData_shouldExtendBundleWhenHashNotEmpty(t *testing.T) {
	snykCodeMock := &FakeSnykCodeApiService{}
	b := BundleImpl{SnykCode: snykCodeMock}

	registeredDocuments := map[lsp.DocumentURI]lsp.TextDocumentItem{}
	registeredDocuments[firstDoc.URI] = firstDoc
	filesNotAdded := b.AddToBundleDocuments(registeredDocuments)
	if filesNotAdded.Files != nil {
		assert.Fail(t, "Unexpected inability to add document to bundle", filesNotAdded)
	}

	// create bundle with first doc
	_ = b.createBundleFromSource()

	// now add a doc
	registeredDocuments[secondDoc.URI] = secondDoc
	b.AddToBundleDocuments(registeredDocuments)

	// execute
	dChan := make(chan lsp2.DiagnosticResult)
	clChan := make(chan lsp2.CodeLensResult)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go b.FetchDiagnosticsData("", &wg, dChan, clChan)

	<-dChan
	<-clChan

	// the bundle documents should have been updated
	assert.Equal(t, b.BundleDocuments[secondDoc.URI].Content, secondDoc.Text)

	// verify that extend bundle has been called on backend service with additional file
	params := snykCodeMock.GetCallParams(0, ExtendBundleWithSourceOperation)
	assert.NotNil(t, params)
	assert.Equal(t, 3, len(params))
	assert.Equal(t, b.BundleHash, params[0])
	files := params[1].(map[lsp.DocumentURI]File)
	assert.Equal(t, files[secondDoc.URI].Content, secondDoc.Text)
}

func TestCodeBundleImpl_FetchDiagnosticsData_shouldRetrieveFromBackend(t *testing.T) {
	snykCodeMock := &FakeSnykCodeApiService{}
	b := BundleImpl{SnykCode: snykCodeMock}
	FakeDiagnosticUri = firstDoc.URI

	registeredDocuments := map[lsp.DocumentURI]lsp.TextDocumentItem{}
	registeredDocuments[firstDoc.URI] = firstDoc
	diagnosticMap := map[lsp.DocumentURI][]lsp2.Diagnostic{}

	b.AddToBundleDocuments(registeredDocuments)
	// execute
	dChan := make(chan lsp2.DiagnosticResult)
	clChan := make(chan lsp2.CodeLensResult)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go b.FetchDiagnosticsData("", &wg, dChan, clChan)
	result := <-dChan
	diagnosticMap[result.Uri] = result.Diagnostics
	<-clChan

	assert.NotNil(t, diagnosticMap)
	diagnostics := diagnosticMap[firstDoc.URI]
	assert.NotNil(t, diagnostics)
	assert.Equal(t, 1, len(diagnostics))
	assert.True(t, reflect.DeepEqual(FakeDiagnostic, diagnostics[0]))

	// verify that extend bundle has been called on backend service with additional file
	params := snykCodeMock.GetCallParams(0, RunAnalysisOperation)
	assert.NotNil(t, params)
	assert.Equal(t, 3, len(params))
	assert.Equal(t, b.BundleHash, params[0])
	assert.Equal(t, 0, params[2])
}

func TestCodeBundleImpl_FetchDiagnosticsData_shouldReturnCodeLenses(t *testing.T) {
	snykCodeMock := &FakeSnykCodeApiService{}
	b := BundleImpl{SnykCode: snykCodeMock}
	FakeDiagnosticUri = firstDoc.URI

	registeredDocuments := map[lsp.DocumentURI]lsp.TextDocumentItem{}
	registeredDocuments[firstDoc.URI] = firstDoc
	b.AddToBundleDocuments(registeredDocuments)

	// execute
	dChan := make(chan lsp2.DiagnosticResult)
	clChan := make(chan lsp2.CodeLensResult)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go b.FetchDiagnosticsData("", &wg, dChan, clChan)
	<-dChan

	codeLensMap := map[lsp.DocumentURI][]lsp.CodeLens{}
	result := <-clChan
	codeLensMap[result.Uri] = result.CodeLenses
	assert.NotEqual(t, 0, len(codeLensMap[firstDoc.URI]))
}

func Test_getShardKey_shouldReturnRootPathOrTokenHash(t *testing.T) {
	// Case 1: rootPath exists
	sampleRootPath := "C:\\GIT\\root"
	// deepcode ignore HardcodedPassword/test: false positive
	token := "TEST"
	assert.Equal(t, util.Hash(sampleRootPath), getShardKey(sampleRootPath, token))

	// Case 2: rootPath empty, token exists
	sampleRootPath = ""
	assert.Equal(t, util.Hash(token), getShardKey(sampleRootPath, token))

	// Case 3: No token, no rootPath set
	sampleRootPath = ""
	// deepcode ignore HardcodedPassword/test: false positive
	token = ""
	assert.Equal(t, "", getShardKey(sampleRootPath, token))
}
