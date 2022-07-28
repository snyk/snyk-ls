package code

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/adrg/xdg"
	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/internal/util"
)

// can we replace them with more succinct higher level integration tests?[keeping them for sanity for the time being]
func setupDocs() (string, lsp.TextDocumentItem, lsp.TextDocumentItem, []byte, []byte) {
	path, _ := os.MkdirTemp(xdg.DataHome, "firstDocTemp")

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

func TestCreateBundle(t *testing.T) {
	t.Run("when < maxFileSize creates bundle", func(t *testing.T) {
		snykCodeMock, dir, c, file := setupCreateBundleTest(t, "java")
		data := strings.Repeat("a", maxFileSize-10)
		err := os.WriteFile(file, []byte(data), 0600)

		if err != nil {
			t.Fatal(t, err)
		}
		_, missingFiles, err := c.createBundle(context.Background(), "testRequestId", dir, []string{file})
		if err != nil {
			t.Fatal(t, err)
		}
		assert.Len(t, missingFiles, 1, "bundle should have 1 missing files")
		assert.Len(t, snykCodeMock.GetAllCalls(CreateBundleOperation), 1, "bundle should called createBundle once")
	})

	t.Run("when too big ignores file", func(t *testing.T) {
		snykCodeMock, dir, c, file := setupCreateBundleTest(t, "java")
		data := strings.Repeat("a", maxFileSize+1)
		err := os.WriteFile(file, []byte(data), 0600)
		if err != nil {
			t.Fatal(t, err)
		}
		_, missingFiles, err := c.createBundle(context.Background(), "testRequestId", dir, []string{file})
		if err != nil {
			t.Fatal(t, err)
		}
		assert.Len(t, missingFiles, 0, "bundle should not have missing files")
		assert.Len(t, snykCodeMock.GetAllCalls(CreateBundleOperation), 0, "bundle shouldn't have called createBundle")
	})

	t.Run("when empty file ignores file", func(t *testing.T) {
		snykCodeMock, dir, c, file := setupCreateBundleTest(t, "java")
		fd, err := os.Create(file)
		t.Cleanup(func() {
			fd.Close()
		})
		if err != nil {
			t.Fatal(t, err)
		}
		_, missingFiles, err := c.createBundle(context.Background(), "testRequestId", dir, []string{file})
		if err != nil {
			t.Fatal(t, err)
		}
		assert.Len(t, missingFiles, 0, "bundle should not have missing files")
		assert.Len(t, snykCodeMock.GetAllCalls(CreateBundleOperation), 0, "bundle shouldn't have called createBundle")
	})

	t.Run("when unsupported ignores file", func(t *testing.T) {
		snykCodeMock, dir, c, file := setupCreateBundleTest(t, "unsupported")
		fd, err := os.Create(file)
		t.Cleanup(func() {
			fd.Close()
		})
		if err != nil {
			t.Fatal(t, err)
		}
		_, missingFiles, err := c.createBundle(context.Background(), "testRequestId", dir, []string{file})
		if err != nil {
			t.Fatal(t, err)
		}
		assert.Len(t, missingFiles, 0, "bundle should not have missing files")
		assert.Len(t, snykCodeMock.GetAllCalls(CreateBundleOperation), 0, "bundle shouldn't have called createBundle")
	})
}

func setupCreateBundleTest(t *testing.T, extension string) (*FakeSnykCodeClient, string, *Scanner, string) {
	testutil.UnitTest(t)
	snykCodeMock := &FakeSnykCodeClient{}
	dir := t.TempDir()
	c := New(
		NewBundler(snykCodeMock, performance.NewTestInstrumentor()),
		&snyk_api.FakeApiClient{CodeEnabled: true},
		error_reporting.NewTestErrorReporter(),
		ux2.NewTestAnalytics(),
	)
	file := filepath.Join(dir, "file."+extension)
	return snykCodeMock, dir, c, file
}

func TestCodeBundleImpl_FetchDiagnosticsData(t *testing.T) {
	t.Run("should create bundle when hash empty", func(t *testing.T) {
		testutil.UnitTest(t)
		snykCodeMock := &FakeSnykCodeClient{}
		c := New(NewBundler(snykCodeMock, performance.NewTestInstrumentor()), &snyk_api.FakeApiClient{CodeEnabled: true}, error_reporting.NewTestErrorReporter(), ux2.NewTestAnalytics())
		path, firstDoc, _, content1, _ := setupDocs()
		docs := []string{uri.PathFromUri(firstDoc.URI)}
		defer os.RemoveAll(path)

		c.UploadAndAnalyze(context.Background(), docs, "")

		// verify that create bundle has been called on backend service
		params := snykCodeMock.GetCallParams(0, CreateBundleOperation)
		assert.NotNil(t, params)
		assert.Equal(t, 1, len(params))
		files := params[0].(map[string]string)
		assert.Equal(t, files[uri.PathFromUri(firstDoc.URI)], util.Hash(content1))
	})

	t.Run("should retrieve from backend", func(t *testing.T) {
		testutil.UnitTest(t)
		snykCodeMock := &FakeSnykCodeClient{}
		c := New(NewBundler(snykCodeMock, performance.NewTestInstrumentor()), &snyk_api.FakeApiClient{CodeEnabled: true}, error_reporting.NewTestErrorReporter(), ux2.NewTestAnalytics())
		diagnosticUri, path := FakeDiagnosticPath()
		defer os.RemoveAll(path)

		issues := c.UploadAndAnalyze(context.Background(), []string{diagnosticUri}, "")

		assert.NotNil(t, issues)
		assert.Equal(t, 1, len(issues))
		assert.True(t, reflect.DeepEqual(FakeIssue, issues[0]))

		// verify that extend bundle has been called on backend service with additional file
		params := snykCodeMock.GetCallParams(0, RunAnalysisOperation)
		assert.NotNil(t, params)
		assert.Equal(t, 3, len(params))
		assert.Equal(t, 0, params[2])
	})

	t.Run("should track analytics", func(t *testing.T) {
		testutil.UnitTest(t)
		snykCodeMock := &FakeSnykCodeClient{}
		analytics := ux2.NewTestAnalytics()
		c := New(NewBundler(snykCodeMock, performance.NewTestInstrumentor()), &snyk_api.FakeApiClient{CodeEnabled: true}, error_reporting.NewTestErrorReporter(), analytics)
		diagnosticUri, path := FakeDiagnosticPath()
		defer os.RemoveAll(path)

		// execute
		c.UploadAndAnalyze(context.Background(), []string{diagnosticUri}, "")

		assert.Len(t, analytics.GetAnalytics(), 1)
		assert.Equal(t, ux2.AnalysisIsReadyProperties{
			AnalysisType: ux2.CodeSecurity,
			Result:       ux2.Success,
		}, analytics.GetAnalytics()[0])
	})
}
