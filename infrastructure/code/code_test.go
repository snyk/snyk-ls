/*
 * © 2022 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package code

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/adrg/xdg"
	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/notification"
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
	t.Run(
		"when < maxFileSize creates bundle", func(t *testing.T) {
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
		},
	)

	t.Run(
		"when too big ignores file", func(t *testing.T) {
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
		},
	)

	t.Run(
		"when empty file ignores file", func(t *testing.T) {
			snykCodeMock, dir, c, file := setupCreateBundleTest(t, "java")
			fd, err := os.Create(file)
			t.Cleanup(
				func() {
					_ = fd.Close()
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			_, missingFiles, err := c.createBundle(context.Background(), "testRequestId", dir, []string{file})
			if err != nil {
				t.Fatal(err)
			}
			assert.Len(t, missingFiles, 0, "bundle should not have missing files")
			assert.Len(t, snykCodeMock.GetAllCalls(CreateBundleOperation), 0, "bundle shouldn't have called createBundle")
		},
	)

	t.Run(
		"when unsupported ignores file", func(t *testing.T) {
			snykCodeMock, dir, c, file := setupCreateBundleTest(t, "unsupported")
			fd, err := os.Create(file)
			t.Cleanup(
				func() {
					_ = fd.Close()
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			_, missingFiles, err := c.createBundle(context.Background(), "testRequestId", dir, []string{file})
			if err != nil {
				t.Fatal(err)
			}
			assert.Len(t, missingFiles, 0, "bundle should not have missing files")
			assert.Len(t, snykCodeMock.GetAllCalls(CreateBundleOperation), 0, "bundle shouldn't have called createBundle")
		},
	)
}

func setupCreateBundleTest(t *testing.T, extension string) (*FakeSnykCodeClient, string, *Scanner, string) {
	testutil.UnitTest(t)
	dir := t.TempDir()
	snykCodeMock, c := setupTestScannerWithNotifications()
	file := filepath.Join(dir, "file."+extension)
	return snykCodeMock, dir, c, file
}

func setupTestScannerWithNotifications() (*FakeSnykCodeClient, *Scanner) {
	snykCodeMock := &FakeSnykCodeClient{}
	scanner := New(
		NewBundler(snykCodeMock, performance.NewTestInstrumentor()),
		&snyk_api.FakeApiClient{CodeEnabled: true},
		error_reporting.NewTestErrorReporter(),
		ux2.NewTestAnalytics(),
		notification.NewScanNotifier(notification.NewNotifier(), "code"),
	)

	return snykCodeMock, scanner
}

func setupTestScanner() (*FakeSnykCodeClient, *notification.MockScanNotifier, *Scanner) {
	snykCodeMock := &FakeSnykCodeClient{}
	mockScanNotifier := notification.NewMockScanNotifier()
	scanner := New(
		NewBundler(snykCodeMock, performance.NewTestInstrumentor()),
		&snyk_api.FakeApiClient{CodeEnabled: true},
		error_reporting.NewTestErrorReporter(),
		ux2.NewTestAnalytics(),
		mockScanNotifier,
	)

	return snykCodeMock, mockScanNotifier, scanner
}

func TestUploadAndAnalyze(t *testing.T) {
	t.Run(
		"should create bundle when hash empty", func(t *testing.T) {
			testutil.UnitTest(t)
			snykCodeMock := &FakeSnykCodeClient{}
			c := New(
				NewBundler(snykCodeMock, performance.NewTestInstrumentor()),
				&snyk_api.FakeApiClient{CodeEnabled: true},
				error_reporting.NewTestErrorReporter(),
				ux2.NewTestAnalytics(),
				notification.NewScanNotifier(notification.NewNotifier(), "code"),
			)
			path, firstDoc, _, content1, _ := setupDocs()
			docs := []string{uri.PathFromUri(firstDoc.URI)}
			defer func(path string) { _ = os.RemoveAll(path) }(path)
			metrics := c.newMetrics(len(docs), time.Time{})

			c.UploadAndAnalyze(context.Background(), docs, "", metrics)

			// verify that create bundle has been called on backend service
			params := snykCodeMock.GetCallParams(0, CreateBundleOperation)
			assert.NotNil(t, params)
			assert.Equal(t, 1, len(params))
			files := params[0].(map[string]string)
			assert.Equal(t, files[uri.PathFromUri(firstDoc.URI)], util.Hash(content1))
		},
	)

	t.Run(
		"should ignore if SAST disabled", func(t *testing.T) {
			testutil.UnitTest(t)
			snykCodeMock := &FakeSnykCodeClient{}
			c := New(
				NewBundler(snykCodeMock, performance.NewTestInstrumentor()),
				&snyk_api.FakeApiClient{CodeEnabled: false},
				error_reporting.NewTestErrorReporter(),
				ux2.NewTestAnalytics(),
				notification.NewScanNotifier(notification.NewNotifier(), "code"),
			)
			path, firstDoc, _, _, _ := setupDocs()
			docs := []string{uri.PathFromUri(firstDoc.URI)}
			defer func(path string) { _ = os.RemoveAll(path) }(path)
			metrics := c.newMetrics(len(docs), time.Time{})

			c.UploadAndAnalyze(context.Background(), docs, "", metrics)

			params := snykCodeMock.GetCallParams(0, CreateBundleOperation)
			assert.Nil(t, params)
		},
	)

	t.Run(
		"should retrieve from backend", func(t *testing.T) {
			testutil.UnitTest(t)
			snykCodeMock := &FakeSnykCodeClient{}
			c := New(
				NewBundler(snykCodeMock, performance.NewTestInstrumentor()),
				&snyk_api.FakeApiClient{CodeEnabled: true},
				error_reporting.NewTestErrorReporter(),
				ux2.NewTestAnalytics(),
				notification.NewScanNotifier(notification.NewNotifier(), "code"),
			)
			diagnosticUri, path := TempWorkdirWithVulnerabilities(t)
			defer func(path string) { _ = os.RemoveAll(path) }(path)
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
		},
	)

	t.Run(
		"should track analytics", func(t *testing.T) {
			testutil.UnitTest(t)
			snykCodeMock := &FakeSnykCodeClient{}
			analytics := ux2.NewTestAnalytics()
			c := New(
				NewBundler(snykCodeMock, performance.NewTestInstrumentor()),
				&snyk_api.FakeApiClient{CodeEnabled: true},
				error_reporting.NewTestErrorReporter(),
				analytics,
				notification.NewScanNotifier(notification.NewNotifier(), "code"),
			)
			diagnosticUri, path := TempWorkdirWithVulnerabilities(t)
			defer func(path string) { _ = os.RemoveAll(path) }(path)
			files := []string{diagnosticUri}
			metrics := c.newMetrics(len(files), time.Now())

			// execute
			c.UploadAndAnalyze(context.Background(), files, "", metrics)

			assert.Len(t, analytics.GetAnalytics(), 1)
			assert.Equal(
				t, ux2.AnalysisIsReadyProperties{
					AnalysisType:      ux2.CodeSecurity,
					Result:            ux2.Success,
					FileCount:         metrics.lastScanFileCount,
					DurationInSeconds: metrics.lastScanDurationInSeconds,
				}, analytics.GetAnalytics()[0],
			)
		},
	)
}

func Test_LoadIgnorePatternsWithIgnoreFilePresent(t *testing.T) {
	expectedPatterns, tempDir, _, _, _ := setupIgnoreWorkspace(t)
	defer func(path string) { _ = os.RemoveAll(path) }(tempDir)
	_, sc := setupTestScannerWithNotifications()

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
	defer func(path string) { _ = os.RemoveAll(path) }(tempDir)
	_, sc := setupTestScannerWithNotifications()

	_, err = sc.loadIgnorePatternsAndCountFiles(tempDir)
	if err != nil {
		t.Fatal(t, err, "Couldn't load .gitignore from workspace")
	}

	assert.Equal(t, []string{""}, sc.ignorePatterns)
}

func Test_GetWorkspaceFolderFiles(t *testing.T) {
	_, tempDir, ignoredFilePath, notIgnoredFilePath, _ := setupIgnoreWorkspace(t)
	defer func(path string) { _ = os.RemoveAll(path) }(tempDir)
	_, sc := setupTestScannerWithNotifications()

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
	defer func(path string) { _ = os.RemoveAll(path) }(tempDir)
	_, sc := setupTestScannerWithNotifications()

	walkedFiles, err := sc.files(tempDir)
	if err != nil {
		t.Fatal(t, err, "Error while registering "+tempDir)
	}
	assert.NotContains(t, walkedFiles, ignoredFileInDir)
}

func Test_CodeScanRunning_ScanCalled_ScansRunSequentially(t *testing.T) {
	// Arrange
	testutil.UnitTest(t)
	_, tempDir, _, _, _ := setupIgnoreWorkspace(t)
	fakeClient, scanner := setupTestScannerWithNotifications()
	fakeClient.AnalysisDuration = time.Second
	wg := sync.WaitGroup{}

	// Act
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			scanner.Scan(context.Background(), "", tempDir)
			wg.Done()
		}()
	}
	wg.Wait()

	// Assert
	assert.Equal(t, 1, fakeClient.maxConcurrentScans)
}

func Test_CodeScanStarted_SnykScanMessageSent(t *testing.T) {
	// Arrange
	testutil.UnitTest(t)
	_, tempDir, _, _, _ := setupIgnoreWorkspace(t)
	_, mockScanNotifier, scanner := setupTestScanner()

	// Act
	scanner.Scan(context.Background(), "", tempDir)

	// Assert
	assert.NotEmpty(t, mockScanNotifier.GetInProgressCalls())
}

//func Test_AnalyzingMessageReturned_InProgressMessageSentToClient(t *testing.T) {
//	// Arrange
//	testutil.UnitTest(t)
//	_, tempDir, _, _, _ := setupIgnoreWorkspace(t)
//	fakeClient, mockScanNotifier, scanner := setupTestScanner()
//	fakeClient.AnalyzingMessageCount = 1
//	// We expect 1 initial message, +1 for every "analyzing" response
//	expectedInProgressMessages := fakeClient.AnalyzingMessageCount + 1
//
//	// Act
//	scanner.Scan(context.Background(), "", tempDir)
//
//	// Assert
//	assert.Len(t, mockScanNotifier.GetInProgressCalls(), expectedInProgressMessages)
//}

func Test_ScanSucceeded_SuccessMessageSent(t *testing.T) {
	// Arrange
	testutil.UnitTest(t)
	_, tempDir, _, _, _ := setupIgnoreWorkspace(t)
	_, mockScanNotifier, scanner := setupTestScanner()

	// Act
	scanner.Scan(context.Background(), "", tempDir)

	// Assert
	assert.Len(t, mockScanNotifier.GetSuccessCalls(), 1)
}

func Test_ScanFailed_ErrorMessageSent(t *testing.T) {
	// Arrange
	testutil.UnitTest(t)
	_, tempDir, _, _, _ := setupIgnoreWorkspace(t)
	mockClient, mockScanNotifier, scanner := setupTestScanner()
	mockClient.FailOnCreateBundle = true

	// Act
	scanner.Scan(context.Background(), "", tempDir)

	// Assert
	assert.Len(t, mockScanNotifier.GetErrorCalls(), 1)
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
	tempDir = t.TempDir()
	filePath := filepath.Join(tempDir, ".gitignore")
	err := os.WriteFile(filePath, []byte(ignorePatterns), 0600)
	if err != nil {
		t.Fatal(t, err, "Couldn't write .gitignore")
	}
	return tempDir
}

func Test_IsEnabled(t *testing.T) {
	scanner := &Scanner{}
	t.Run(
		"should return true if Snyk Code is generally enabled", func(t *testing.T) {
			config.CurrentConfig().SetSnykCodeEnabled(true)
			enabled := scanner.IsEnabled()
			assert.True(t, enabled)
		},
	)
	t.Run(
		"should return true if Snyk Code Quality is enabled", func(t *testing.T) {
			config.CurrentConfig().SetSnykCodeEnabled(false)
			config.CurrentConfig().EnableSnykCodeQuality(true)
			config.CurrentConfig().EnableSnykCodeSecurity(false)
			enabled := scanner.IsEnabled()
			assert.True(t, enabled)
		},
	)
	t.Run(
		"should return true if Snyk Code Security is enabled", func(t *testing.T) {
			config.CurrentConfig().SetSnykCodeEnabled(false)
			config.CurrentConfig().EnableSnykCodeQuality(false)
			config.CurrentConfig().EnableSnykCodeSecurity(true)
			enabled := scanner.IsEnabled()
			assert.True(t, enabled)
		},
	)
	t.Run(
		"should return false if Snyk Code is disabled and Snyk Code Quality and Security are not enabled",
		func(t *testing.T) {
			config.CurrentConfig().SetSnykCodeEnabled(false)
			config.CurrentConfig().EnableSnykCodeQuality(false)
			config.CurrentConfig().EnableSnykCodeSecurity(false)
			enabled := scanner.IsEnabled()
			assert.False(t, enabled)
		},
	)
}
