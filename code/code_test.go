package code_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/code"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/internal/observability/infrastructure/sentry"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/observability/ux"
	"github.com/snyk/snyk-ls/internal/uri"
	lsp2 "github.com/snyk/snyk-ls/lsp"
)

// can we replace them with more succinct higher level integration tests?[keeping them for sanity for the time being]
func setupDocs() (string, lsp.TextDocumentItem, lsp.TextDocumentItem, []byte, []byte) {
	path, _ := os.MkdirTemp(os.TempDir(), "firstDocTemp")

	content1 := []byte("test1")
	_ = os.WriteFile(path+string(os.PathSeparator)+"test1.java", content1, 0660)

	content2 := []byte("test2")
	_ = os.WriteFile(path+string(os.PathSeparator)+"test2.java", content2, 0660)

	firstDoc := lsp.TextDocumentItem{
		URI: uri.PathToUri(filepath.Join(path, "test1.java")),
	}

	secondDoc := lsp.TextDocumentItem{
		URI: uri.PathToUri(filepath.Join(path, "test2.java")),
	}
	return path, firstDoc, secondDoc, content1, content2
}

func TestCodeBundleImpl_FetchDiagnosticsData(t *testing.T) {
	t.Run("should create bundle when hash empty", func(t *testing.T) {
		snykCodeMock := &code.FakeSnykCodeClient{}
		c := code.NewSnykCode(code.NewBundler(snykCodeMock, &performance.TestInstrumentor{}), &code.FakeApiClient{CodeEnabled: true}, sentry.NewTestErrorReporter(), ux.NewNoopRecordingClient())
		path, firstDoc, _, content1, _ := setupDocs()
		registeredDocuments := []lsp.DocumentURI{firstDoc.URI}
		defer os.RemoveAll(path)

		dChan := make(chan lsp2.DiagnosticResult)
		hoverChan := make(chan hover.DocumentHovers)
		wg := sync.WaitGroup{}
		wg.Add(1)

		go c.UploadAndAnalyze(context.Background(), registeredDocuments, &wg, "", dChan, hoverChan)

		<-dChan

		// verify that create bundle has been called on backend service
		params := snykCodeMock.GetCallParams(0, code.CreateBundleWithSourceOperation)
		assert.NotNil(t, params)
		assert.Equal(t, 1, len(params))
		files := params[0].(map[lsp.DocumentURI]code.BundleFile)
		assert.Equal(t, files[firstDoc.URI].Content, string(content1))
	})

	t.Run("should retrieve from backend", func(t *testing.T) {
		snykCodeMock := &code.FakeSnykCodeClient{}
		c := code.NewSnykCode(code.NewBundler(snykCodeMock, &performance.TestInstrumentor{}), &code.FakeApiClient{CodeEnabled: true}, sentry.NewTestErrorReporter(), ux.NewNoopRecordingClient())
		diagnosticUri, path := code.FakeDiagnosticUri()
		defer os.RemoveAll(path)
		diagnosticMap := map[lsp.DocumentURI][]lsp2.Diagnostic{}

		// execute
		dChan := make(chan lsp2.DiagnosticResult)
		hoverChan := make(chan hover.DocumentHovers)
		wg := sync.WaitGroup{}
		wg.Add(1)

		go c.UploadAndAnalyze(context.Background(), []lsp.DocumentURI{diagnosticUri}, &wg, "", dChan, hoverChan)
		result := <-dChan
		diagnosticMap[result.Uri] = result.Diagnostics

		assert.NotNil(t, diagnosticMap)
		diagnostics := diagnosticMap[diagnosticUri]
		assert.NotNil(t, diagnostics)
		assert.Equal(t, 1, len(diagnostics))
		assert.True(t, reflect.DeepEqual(code.FakeDiagnostic, diagnostics[0]))

		// verify that extend bundle has been called on backend service with additional file
		params := snykCodeMock.GetCallParams(0, code.RunAnalysisOperation)
		assert.NotNil(t, params)
		assert.Equal(t, 3, len(params))
		assert.Equal(t, 0, params[2])
	})

	t.Run("should track analytics", func(t *testing.T) {
		snykCodeMock := &code.FakeSnykCodeClient{}
		analytics := ux.NewNoopRecordingClient()
		c := code.NewSnykCode(code.NewBundler(snykCodeMock, &performance.TestInstrumentor{}), &code.FakeApiClient{CodeEnabled: true}, sentry.NewTestErrorReporter(), analytics)
		diagnosticUri, path := code.FakeDiagnosticUri()
		defer os.RemoveAll(path)

		// execute
		dChan := make(chan lsp2.DiagnosticResult, 100)
		hoverChan := make(chan hover.DocumentHovers, 100)
		wg := sync.WaitGroup{}

		c.UploadAndAnalyze(context.Background(), []lsp.DocumentURI{diagnosticUri}, &wg, "", dChan, hoverChan)

		assert.Len(t, analytics.GetAnalytics(), 1)
		assert.Equal(t, ux.AnalysisIsReadyProperties{
			AnalysisType: ux.CodeSecurity,
			Result:       ux.Success,
		}, analytics.GetAnalytics()[0])
	})
}
