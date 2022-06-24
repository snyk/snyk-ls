package code_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/code"
	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace/deleteme"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/observability/ux"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/internal/util"
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

/* 	t.Run("when too big ignores file", func(t *testing.T) {
	snykCodeService := &FakeSnykCodeClient{}
	var bundler = BundleUploader{Scanner: snykCodeService, instrumentor: performance.NewTestInstrumentor()}
	documentURI, bundleFile := createTempFileInDir("bundleDoc.java", 1024*1024+1, temporaryDir)
	bundleFileMap := map[lsp.DocumentURI]BundleFile{}
	bundleFileMap[documentURI] = bundleFile

	_, err := bundler.Upload(context.Background(), Bundle{Scanner: snykCodeService, missingFiles: []lsp.DocumentURI{documentURI}}, bundleFileMap)

	assert.False(t, snykCodeService.HasExtendedBundle)
	assert.Nil(t, err)
})

t.Run("when empty file ignores file", func(t *testing.T) {
	snykCodeService := &FakeSnykCodeClient{}
	var bundler = BundleUploader{Scanner: snykCodeService, instrumentor: performance.NewTestInstrumentor()}

	documentURI, bundleFile := createTempFileInDir("bundleDoc.java", 0, temporaryDir)
	bundleFileMap := map[lsp.DocumentURI]BundleFile{}
	bundleFileMap[documentURI] = bundleFile

	_, err := bundler.Upload(context.Background(), Bundle{Scanner: snykCodeService, missingFiles: []lsp.DocumentURI{documentURI}}, bundleFileMap)

	assert.False(t, snykCodeService.HasExtendedBundle)
	assert.Nil(t, err)
})

t.Run("when unsupported ignores file", func(t *testing.T) {
	snykCodeService := &FakeSnykCodeClient{}
	var bundler = BundleUploader{Scanner: snykCodeService, instrumentor: performance.NewTestInstrumentor()}

	documentURI, bundleFile := createTempFileInDir("bundleDoc.mr_robot", 1, temporaryDir)
	bundleFileMap := map[lsp.DocumentURI]BundleFile{}
	bundleFileMap[documentURI] = bundleFile

	_, err := bundler.Upload(context.Background(), Bundle{Scanner: snykCodeService, missingFiles: []lsp.DocumentURI{documentURI}}, bundleFileMap)

	assert.False(t, snykCodeService.HasExtendedBundle)
	assert.Nil(t, err)
})

*/

func TestCodeBundleImpl_FetchDiagnosticsData(t *testing.T) {
	t.Run("should create bundle when hash empty", func(t *testing.T) {
		config.SetCurrentConfig(config.New())
		snykCodeMock := &code.FakeSnykCodeClient{}
		c := code.NewSnykCode(code.NewBundler(snykCodeMock, performance.NewTestInstrumentor()), &code.FakeApiClient{CodeEnabled: true}, error_reporting.NewTestErrorReporter(), ux.NewTestAnalytics())
		path, firstDoc, _, content1, _ := setupDocs()
		docs := []string{uri.PathFromUri(firstDoc.URI)}
		defer os.RemoveAll(path)

		c.UploadAndAnalyze(context.Background(), docs, "", deleteme.NoopResultProcessor)

		// verify that create bundle has been called on backend service
		params := snykCodeMock.GetCallParams(0, code.CreateBundleWithSourceOperation)
		assert.NotNil(t, params)
		assert.Equal(t, 1, len(params))
		files := params[0].(map[string]string)
		assert.Equal(t, files[uri.PathFromUri(firstDoc.URI)], util.Hash(content1))
	})

	t.Run("should retrieve from backend", func(t *testing.T) {
		snykCodeMock := &code.FakeSnykCodeClient{}
		c := code.NewSnykCode(code.NewBundler(snykCodeMock, performance.NewTestInstrumentor()), &code.FakeApiClient{CodeEnabled: true}, error_reporting.NewTestErrorReporter(), ux.NewTestAnalytics())
		diagnosticUri, path := code.FakeDiagnosticUri()
		defer os.RemoveAll(path)

		// execute
		var diagnostics []lsp2.Diagnostic
		output := func(issues []lsp2.Diagnostic, hovers []hover.DocumentHovers) {
			diagnostics = issues
		}

		c.UploadAndAnalyze(context.Background(), []string{diagnosticUri}, "", output)

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
		analytics := ux.NewTestAnalytics()
		c := code.NewSnykCode(code.NewBundler(snykCodeMock, performance.NewTestInstrumentor()), &code.FakeApiClient{CodeEnabled: true}, error_reporting.NewTestErrorReporter(), analytics)
		diagnosticUri, path := code.FakeDiagnosticUri()
		defer os.RemoveAll(path)

		// execute
		c.UploadAndAnalyze(context.Background(), []string{diagnosticUri}, "", deleteme.NoopResultProcessor)

		assert.Len(t, analytics.GetAnalytics(), 1)
		assert.Equal(t, ux.AnalysisIsReadyProperties{
			AnalysisType: ux.CodeSecurity,
			Result:       ux.Success,
		}, analytics.GetAnalytics()[0])
	})
}
