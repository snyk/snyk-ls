package code

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"testing"

	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/uri"
	lsp2 "github.com/snyk/snyk-ls/lsp"
	"github.com/snyk/snyk-ls/util"
)

func setupDocs(t *testing.T) (lsp.TextDocumentItem, lsp.TextDocumentItem, []byte, []byte) {
	path := t.TempDir()
	content1 := []byte("test1")
	err := os.WriteFile(path+string(os.PathSeparator)+"test1.java", content1, 0660)
	if err != nil {
		t.Fatal("Couldn't create test file1")
	}

	content2 := []byte("test2")
	err = os.WriteFile(path+string(os.PathSeparator)+"test2.java", content2, 0660)
	if err != nil {
		t.Fatal("Couldn't create test file2")
	}

	firstDoc := lsp.TextDocumentItem{
		URI: uri.PathToUri(filepath.Join(path, "test1.java")),
	}

	secondDoc := lsp.TextDocumentItem{
		URI: uri.PathToUri(filepath.Join(path, "test2.java")),
	}
	return firstDoc, secondDoc, content1, content2
}

func Test_createBundleFromSource_shouldReturnNonEmptyBundleHash(t *testing.T) {
	b := BundleImpl{
		SnykCode: &FakeSnykCodeApiService{},
	}
	b.BundleDocuments = map[lsp.DocumentURI]File{}
	registeredDocuments := map[lsp.DocumentURI]bool{}
	firstDoc, _, _, _ := setupDocs(t)
	registeredDocuments[firstDoc.URI] = true
	ctx := context.Background()
	_ = b.AddToBundleDocuments(ctx, registeredDocuments)
	_ = b.createBundleFromSource(ctx)
	assert.NotEqual(t, "", b.BundleHash)
}

func Test_AddToBundleDocuments_shouldNotAddDocumentToBundleIfTooBig(t *testing.T) {
	b, registeredDocuments, _, _ := setupBundleForTesting(t, 1024*1024+1)
	ctx := context.Background()
	_ = b.AddToBundleDocuments(ctx, registeredDocuments)

	assert.Empty(t, b.missingFiles)
	assert.Empty(t, b.BundleDocuments)
}

func Test_AddToBundleDocuments_shouldNotAddDocumentToBundleIfEmpty(t *testing.T) {
	b, registeredDocuments, _, _ := setupBundleForTesting(t, 0)
	ctx := context.Background()

	_ = b.AddToBundleDocuments(ctx, registeredDocuments)

	assert.Empty(t, b.missingFiles)
	assert.Empty(t, b.BundleDocuments)
}

func Test_AddToBundleDocuments_shouldReturnNotAddedFileIfBundleGreaterThanMaxPayloadSize(t *testing.T) {
	b, registeredDocuments, path, content := setupBundleForTesting(t, maxFileSize)
	defer os.RemoveAll(path)
	for i := 0; i < (maxBundleSize / maxFileSize); i++ {
		fileName := strconv.Itoa(i) + ".java"
		filePath := path + string(os.PathSeparator) + fileName
		err := os.WriteFile(filePath, content, 0660)
		if err != nil {
			t.Fatal("Couldn't create test file " + fileName)
		}
		documentUri := uri.PathToUri(filePath)
		registeredDocuments[documentUri] = true
	}
	ctx := context.Background()

	filesNotAdded := b.AddToBundleDocuments(ctx, registeredDocuments)

	assert.Len(t, filesNotAdded.Files, 2)
}

func Test_AddToBundleDocuments_shouldNotAddUnsupportedFileType(t *testing.T) {
	b, registeredDocuments, path, _ := setupBundleForTesting(t, 1) // this adds one file to bundle documents
	defer os.RemoveAll(path)
	documentUri := uri.PathToUri("1")
	registeredDocuments[documentUri] = true
	ctx := context.Background()

	filesNotAdded := b.AddToBundleDocuments(ctx, registeredDocuments)

	assert.Len(t, filesNotAdded.Files, 0)
	assert.Len(t, b.BundleDocuments, 1)
}

func Test_getSize_shouldReturn0ForEmptyBundle(t *testing.T) {
	b, registeredDocuments, path, _ := setupBundleForTesting(t, 0)
	defer os.RemoveAll(path)
	ctx := context.Background()

	_ = b.AddToBundleDocuments(ctx, registeredDocuments)

	size := b.getSize()
	assert.Equal(t, 0, size)
}

func Test_getSize_shouldReturnTotalBundleSize(t *testing.T) {
	b, registeredDocuments, path, _ := setupBundleForTesting(t, 1)
	defer os.RemoveAll(path)
	ctx := context.Background()
	_ = b.AddToBundleDocuments(ctx, registeredDocuments)

	var req = extendBundleRequest{Files: b.BundleDocuments}
	jsonBytes, err := json.Marshal(req)
	if err != nil {
		assert.Fail(t, err.Error(), "Couldn't marshal ", req)
	}

	size := b.getSize()

	assert.Equal(t, len(jsonBytes), size)
}

func setupBundleForTesting(t *testing.T, contentSize int) (BundleImpl, map[lsp.DocumentURI]bool, string, []byte) {
	b := BundleImpl{
		SnykCode: &FakeSnykCodeApiService{},
	}
	b.BundleHash = "test-Hash"
	b.BundleDocuments = map[lsp.DocumentURI]File{}
	registeredDocuments := map[lsp.DocumentURI]bool{}

	buf := new(bytes.Buffer)
	buf.Grow(contentSize)
	for i := 0; i < contentSize; i++ {
		buf.WriteByte('a')
	}
	dir := t.TempDir()
	filePath := dir + string(os.PathSeparator) + "bundleDoc.java"
	bundleDoc := lsp.TextDocumentItem{URI: uri.PathToUri(filePath)}
	err := os.WriteFile(filePath, buf.Bytes(), 0660)
	if err != nil {
		t.Fatal("Couldn't write test file")
	}
	registeredDocuments[bundleDoc.URI] = true
	return b, registeredDocuments, dir, buf.Bytes()
}

func TestCodeBundleImpl_FetchDiagnosticsData_shouldCreateBundleWhenHashEmpty(t *testing.T) {
	snykCodeMock := &FakeSnykCodeApiService{}
	b := BundleImpl{SnykCode: snykCodeMock}
	b.BundleHash = ""
	registeredDocuments := map[lsp.DocumentURI]bool{}
	firstDoc, _, content1, _ := setupDocs(t)
	registeredDocuments[firstDoc.URI] = true
	ctx := context.Background()
	b.AddToBundleDocuments(ctx, registeredDocuments)

	dChan := make(chan lsp2.DiagnosticResult)
	hoverChan := make(chan lsp2.Hover)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go b.FetchDiagnosticsData(ctx, "", &wg, dChan, hoverChan)

	<-dChan

	assert.Equal(t, 0, len(b.missingFiles))

	// verify that create bundle has been called on backend service
	params := snykCodeMock.GetCallParams(0, CreateBundleWithSourceOperation)
	assert.NotNil(t, params)
	assert.Equal(t, 1, len(params))
	files := params[0].(map[lsp.DocumentURI]File)
	assert.Equal(t, files[firstDoc.URI].Content, string(content1))
}

func TestCodeBundleImpl_FetchDiagnosticsData_shouldExtendBundleWhenHashNotEmpty(t *testing.T) {
	snykCodeMock := &FakeSnykCodeApiService{}
	b := BundleImpl{SnykCode: snykCodeMock}
	firstDoc, secondDoc, _, content2 := setupDocs(t)
	registeredDocuments := map[lsp.DocumentURI]bool{}
	registeredDocuments[firstDoc.URI] = true
	ctx := context.Background()
	filesNotAdded := b.AddToBundleDocuments(ctx, registeredDocuments)
	if filesNotAdded.Files != nil {
		assert.Fail(t, "Unexpected inability to add document to bundle", filesNotAdded)
	}

	// create bundle with first doc
	_ = b.createBundleFromSource(ctx)

	// now add a doc
	registeredDocuments[secondDoc.URI] = true
	b.AddToBundleDocuments(ctx, registeredDocuments)

	// execute
	dChan := make(chan lsp2.DiagnosticResult)
	hoverChan := make(chan lsp2.Hover)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go b.FetchDiagnosticsData(ctx, "", &wg, dChan, hoverChan)

	<-dChan

	// the bundle documents should have been updated
	assert.Equal(t, b.BundleDocuments[secondDoc.URI].Content, string(content2))

	// verify that extend bundle has been called on backend service with additional file
	params := snykCodeMock.GetCallParams(0, ExtendBundleWithSourceOperation)
	assert.NotNil(t, params)
	assert.Equal(t, 3, len(params))
	assert.Equal(t, b.BundleHash, params[0])
	files := params[1].(map[lsp.DocumentURI]File)
	assert.Equal(t, files[secondDoc.URI].Content, string(content2))
}

func TestCodeBundleImpl_FetchDiagnosticsData_shouldRetrieveFromBackend(t *testing.T) {
	snykCodeMock := &FakeSnykCodeApiService{}
	diagnosticUri, path := FakeDiagnosticUri()
	defer os.RemoveAll(path)
	b := BundleImpl{SnykCode: snykCodeMock}
	ctx := context.Background()

	bundleDocs := map[lsp.DocumentURI]bool{}
	bundleDocs[diagnosticUri] = true
	diagnosticMap := map[lsp.DocumentURI][]lsp2.Diagnostic{}

	b.AddToBundleDocuments(ctx, bundleDocs)
	// execute
	dChan := make(chan lsp2.DiagnosticResult)
	hoverChan := make(chan lsp2.Hover)
	wg := sync.WaitGroup{}
	wg.Add(1)

	go b.FetchDiagnosticsData(ctx, "", &wg, dChan, hoverChan)
	result := <-dChan
	diagnosticMap[result.Uri] = result.Diagnostics

	assert.NotNil(t, diagnosticMap)
	diagnostics := diagnosticMap[diagnosticUri]
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

func Test_getShardKey_shouldReturnRootPathHash(t *testing.T) {
	// Case 1: rootPath exists
	sampleRootPath := "C:\\GIT\\root"
	// deepcode ignore HardcodedPassword/test: false positive
	token := "TEST"
	assert.Equal(t, util.Hash([]byte(sampleRootPath)), getShardKey(sampleRootPath, token))
}

func Test_getShardKey_shouldReturnTokenHash(t *testing.T) {
	// Case 2: rootPath empty, token exists
	sampleRootPath := ""
	// deepcode ignore HardcodedPassword/test: false positive
	token := "TEST"
	assert.Equal(t, util.Hash([]byte(token)), getShardKey(sampleRootPath, token))
}

func Test_getShardKey_shouldReturnEmptyShardKey(t *testing.T) {
	// Case 3: No token, no rootPath set
	sampleRootPath := ""
	// deepcode ignore HardcodedPassword/test: false positive
	token := ""
	assert.Equal(t, "", getShardKey(sampleRootPath, token))
}
