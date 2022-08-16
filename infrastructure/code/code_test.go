package code

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

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
			t.Fatal(err)
		}
		_, missingFiles, err := c.createBundle(context.Background(), "testRequestId", dir, []string{file})
		if err != nil {
			t.Fatal(err)
		}
		assert.Len(t, missingFiles, 1, "bundle should have 1 missing files")
		assert.Len(t, snykCodeMock.GetAllCalls(CreateBundleOperation), 1, "bundle should called createBundle once")
	})

	t.Run("when too big ignores file", func(t *testing.T) {
		snykCodeMock, dir, c, file := setupCreateBundleTest(t, "java")
		data := strings.Repeat("a", maxFileSize+1)
		err := os.WriteFile(file, []byte(data), 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, missingFiles, err := c.createBundle(context.Background(), "testRequestId", dir, []string{file})
		if err != nil {
			t.Fatal(err)
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
			t.Fatal(err)
		}
		_, missingFiles, err := c.createBundle(context.Background(), "testRequestId", dir, []string{file})
		if err != nil {
			t.Fatal(err)
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
			t.Fatal(err)
		}
		_, missingFiles, err := c.createBundle(context.Background(), "testRequestId", dir, []string{file})
		if err != nil {
			t.Fatal(err)
		}
		assert.Len(t, missingFiles, 0, "bundle should not have missing files")
		assert.Len(t, snykCodeMock.GetAllCalls(CreateBundleOperation), 0, "bundle shouldn't have called createBundle")
	})
}

func setupCreateBundleTest(t *testing.T, extension string) (*FakeSnykCodeClient, string, *Scanner, string) {
	testutil.UnitTest(t)
	dir := t.TempDir()
	snykCodeMock, c := setupTestScanner()
	file := filepath.Join(dir, "file."+extension)
	return snykCodeMock, dir, c, file
}

func setupTestScanner() (*FakeSnykCodeClient, *Scanner) {
	snykCodeMock := &FakeSnykCodeClient{}
	scanner := New(
		NewBundler(snykCodeMock, performance.NewTestInstrumentor()),
		&snyk_api.FakeApiClient{CodeEnabled: true},
		error_reporting.NewTestErrorReporter(),
		ux2.NewTestAnalytics(),
	)

	return snykCodeMock, scanner
}

func TestCodeBundleImpl_FetchDiagnosticsData(t *testing.T) {
	t.Run("should create bundle when hash empty", func(t *testing.T) {
		testutil.UnitTest(t)
		snykCodeMock := &FakeSnykCodeClient{}
		c := New(NewBundler(snykCodeMock, performance.NewTestInstrumentor()), &snyk_api.FakeApiClient{CodeEnabled: true}, error_reporting.NewTestErrorReporter(), ux2.NewTestAnalytics())
		path, firstDoc, _, content1, _ := setupDocs()
		docs := []string{uri.PathFromUri(firstDoc.URI)}
		defer os.RemoveAll(path)
		metrics := c.newMetrics(len(docs), time.Time{})

		c.UploadAndAnalyze(context.Background(), docs, "", metrics)

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
		diagnosticUri, path := FakeDiagnosticPath(t)
		defer os.RemoveAll(path)
		files := []string{diagnosticUri}
		metrics := c.newMetrics(len(files), time.Time{})

		issues := c.UploadAndAnalyze(context.Background(), files, "", metrics)

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
		diagnosticUri, path := FakeDiagnosticPath(t)
		defer os.RemoveAll(path)
		files := []string{diagnosticUri}
		metrics := c.newMetrics(len(files), time.Now())

		// execute
		c.UploadAndAnalyze(context.Background(), files, "", metrics)

		assert.Len(t, analytics.GetAnalytics(), 1)
		assert.Equal(t, ux2.AnalysisIsReadyProperties{
			AnalysisType:      ux2.CodeSecurity,
			Result:            ux2.Success,
			FileCount:         metrics.lastScanFileCount,
			DurationInSeconds: metrics.lastScanDurationInSeconds,
		}, analytics.GetAnalytics()[0])
	})
}

func Test_LoadIgnorePatternsWithIgnoreFilePresent(t *testing.T) {
	expectedPatterns, tempDir, _, _, _ := setupIgnoreWorkspace(t)
	defer os.RemoveAll(tempDir)
	_, sc := setupTestScanner()

	_, err := sc.loadIgnorePatternsAndCountFiles(tempDir)
	if err != nil {
		t.Fatal(t, err, "Couldn't load .gitignore from workspace "+tempDir)
	}

	assert.Equal(t, strings.Split(expectedPatterns, "\n"), sc.ignorePatterns)
}

func Test_LoadIgnorePatternsWithoutIgnoreFilePresent(t *testing.T) {
	tempDir, err := os.MkdirTemp(xdg.DataHome, "loadIgnoreTest")
	if err != nil {
		t.Fatal("can't create temp dir")
	}
	defer os.RemoveAll(tempDir)
	_, sc := setupTestScanner()

	_, err = sc.loadIgnorePatternsAndCountFiles(tempDir)
	if err != nil {
		t.Fatal(t, err, "Couldn't load .gitignore from workspace")
	}

	assert.Equal(t, []string{""}, sc.ignorePatterns)
}

func Test_GetWorkspaceFolderFiles(t *testing.T) {
	_, tempDir, ignoredFilePath, notIgnoredFilePath, _ := setupIgnoreWorkspace(t)
	defer os.RemoveAll(tempDir)
	_, sc := setupTestScanner()

	files, err := sc.files(tempDir)
	if err != nil {
		t.Fatal(t, err, "Error getting workspace folder files: "+tempDir)
	}

	assert.Len(t, files, 2)
	assert.Contains(t, files, notIgnoredFilePath)
	assert.NotContains(t, files, ignoredFilePath)
}

func Test_GetWorkspaceFiles_SkipIgnoredDirs(t *testing.T) {
	_, tempDir, _, _, ignoredFileInDir := setupIgnoreWorkspace(t)
	defer os.RemoveAll(tempDir)
	_, sc := setupTestScanner()

	walkedFiles, err := sc.files(tempDir)
	if err != nil {
		t.Fatal(t, err, "Error while registering "+tempDir)
	}
	assert.NotContains(t, walkedFiles, ignoredFileInDir)
}

func setupIgnoreWorkspace(t *testing.T) (expectedPatterns string, tempDir string, ignoredFilePath string, notIgnoredFilePath string, ignoredFileInDir string) {
	expectedPatterns = "*.xml\n**/*.txt\nbin"
	tempDir = writeTestGitIgnore(expectedPatterns, t)

	ignoredFilePath = filepath.Join(tempDir, "ignored.xml")
	err := os.WriteFile(ignoredFilePath, []byte("test"), 0600)
	if err != nil {
		t.Fatal(t, err, "Couldn't write ignored file ignored.xml")
	}
	notIgnoredFilePath = filepath.Join(tempDir, "not-ignored.java")
	err = os.WriteFile(notIgnoredFilePath, []byte("test"), 0600)
	if err != nil {
		t.Fatal(t, err, "Couldn't write ignored file not-ignored.java")
	}
	ignoredDir := filepath.Join(tempDir, "bin")
	err = os.Mkdir(ignoredDir, 0755)
	if err != nil {
		t.Fatal(t, err, "Couldn't write ignoreDirectory %s", ignoredDir)
	}
	ignoredFileInDir = filepath.Join(ignoredDir, "shouldNotBeWalked.java")
	err = os.WriteFile(ignoredFileInDir, []byte("public bla"), 0600)
	if err != nil {
		t.Fatal(t, err, "Couldn't write ignored file not-ignored.java")
	}
	return expectedPatterns, tempDir, ignoredFilePath, notIgnoredFilePath, ignoredFileInDir
}

func writeTestGitIgnore(ignorePatterns string, t *testing.T) (tempDir string) {
	tempDir, err := os.MkdirTemp(xdg.DataHome, "loadIgnorePatternsAndCountFiles")
	if err != nil {
		t.Fatal(t, err, "Couldn't create temp dir")
	}
	filePath := filepath.Join(tempDir, ".gitignore")
	err = os.WriteFile(filePath, []byte(ignorePatterns), 0600)
	if err != nil {
		t.Fatal(t, err, "Couldn't write .gitignore")
	}
	return tempDir
}
