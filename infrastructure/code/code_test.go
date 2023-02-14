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
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/data_structure"
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
			)
			path, firstDoc, _, content1, _ := setupDocs()
			docs := []string{uri.PathFromUri(firstDoc.URI)}
			defer func(path string) { _ = os.RemoveAll(path) }(path)
			metrics := c.newMetrics(len(docs), time.Time{})

			_, _ = c.UploadAndAnalyze(context.Background(), docs, "", metrics)

			// verify that create bundle has been called on backend service
			params := snykCodeMock.GetCallParams(0, CreateBundleOperation)
			assert.NotNil(t, params)
			assert.Equal(t, 1, len(params))
			files := params[0].(map[string]string)
			assert.Equal(t, files[uri.PathFromUri(firstDoc.URI)], util.Hash(content1))
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
			)
			diagnosticUri, path := TempWorkdirWithVulnerabilities(t)
			defer func(path string) { _ = os.RemoveAll(path) }(path)
			files := []string{diagnosticUri}
			metrics := c.newMetrics(len(files), time.Time{})

			issues, _ := c.UploadAndAnalyze(context.Background(), files, "", metrics)

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
			)
			diagnosticUri, path := TempWorkdirWithVulnerabilities(t)
			defer func(path string) { _ = os.RemoveAll(path) }(path)
			files := []string{diagnosticUri}
			metrics := c.newMetrics(len(files), time.Now())

			// execute
			_, _ = c.UploadAndAnalyze(context.Background(), files, "", metrics)

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

func Test_IgnoresWithNegationInSnykCode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	repobase := filepath.Join(dir, "temp", "repobase")
	err := os.MkdirAll(repobase, 0755)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(repobase, ".gitignore"), []byte("!temp"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(repobase, "file1.java"), []byte("any data we would like"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	codeClientMock, scanner := setupTestScanner()

	_, _ = scanner.Scan(context.Background(), "", repobase)

	calls := codeClientMock.GetAllCalls("extendBundleWithSource")
	assert.Len(t, calls, 1)
	assert.Contains(t, scanner.ignorePatterns, "!**/temp")
}

func Test_IgnoresInSnykCode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	repobase := filepath.Join(dir, "temp", "repobase")
	err := os.MkdirAll(repobase, 0755)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(repobase, ".gitignore"), []byte("temp"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(repobase, "file1.java"), []byte("any data we would like"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	codeClientMock, scanner := setupTestScanner()

	_, _ = scanner.Scan(context.Background(), "", repobase)

	calls := codeClientMock.GetAllCalls("extendBundleWithSource")
	assert.Len(t, calls, 1)
}

func Test_LoadIgnorePatternsWithoutIgnoreFilePresent(t *testing.T) {
	tempDir, err := os.MkdirTemp(xdg.DataHome, "loadIgnoreTest")
	if err != nil {
		t.Fatal("can't create temp dir")
	}
	defer func(path string) { _ = os.RemoveAll(path) }(tempDir)
	_, sc := setupTestScanner()

	_, err = sc.loadIgnorePatternsAndCountFiles(tempDir)
	if err != nil {
		t.Fatal(t, err, "Couldn't load .gitignore from workspace")
	}

	assert.Equal(t, getDefaultIgnorePatterns(), sc.ignorePatterns)
}

func Test_GetWorkspaceFolderFiles(t *testing.T) {
	_, tempDir, ignoredFilePath, notIgnoredFilePath, _ := setupIgnoreWorkspace(t)
	defer func(path string) { _ = os.RemoveAll(path) }(tempDir)
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
	defer func(path string) { _ = os.RemoveAll(path) }(tempDir)
	_, sc := setupTestScanner()

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
	fakeClient, scanner := setupTestScanner()
	fakeClient.AnalysisDuration = time.Second
	wg := sync.WaitGroup{}

	// Act
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			_, _ = scanner.Scan(context.Background(), "", tempDir)
			wg.Done()
		}()
	}
	wg.Wait()

	// Assert
	assert.Equal(t, 1, fakeClient.maxConcurrentScans)
}

func Test_Scan_ShouldntRunIfSastDisabled(t *testing.T) {
	testutil.UnitTest(t)
	snykCodeMock := &FakeSnykCodeClient{}
	c := New(
		NewBundler(snykCodeMock, performance.NewTestInstrumentor()),
		&snyk_api.FakeApiClient{CodeEnabled: false},
		error_reporting.NewTestErrorReporter(),
		ux2.NewTestAnalytics(),
	)
	_, tempDir, _, _, _ := setupIgnoreWorkspace(t)

	_, _ = c.Scan(context.Background(), "", tempDir)

	params := snykCodeMock.GetCallParams(0, CreateBundleOperation)
	assert.Nil(t, params)
}

func Test_LoadIgnorePatternsAndCountFiles_RelativePathIgnores(t *testing.T) {
	testutil.UnitTest(t)
	tempDir := writeTestGitIgnore("", t)
	subDir := filepath.Join(tempDir, "evilfolder")
	_ = os.Mkdir(subDir, 0755)
	writeGitIgnoreIntoDir("*", t, subDir)
	expectedSubDirPattern, err := filepath.Rel(tempDir, filepath.Join(subDir, "**/*"))
	assert.NoError(t, err)
	expectedSubDirPattern = filepath.ToSlash(expectedSubDirPattern)

	sc := Scanner{}
	_, err = sc.loadIgnorePatternsAndCountFiles(tempDir)

	assert.NoError(t, err)
	assert.Contains(t, sc.ignorePatterns, expectedSubDirPattern)
	assert.Len(t, sc.ignorePatterns, len(getDefaultIgnorePatterns())+1)
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
	writeGitIgnoreIntoDir(ignorePatterns, t, tempDir)
	return tempDir
}

func writeGitIgnoreIntoDir(ignorePatterns string, t *testing.T, tempDir string) {
	filePath := filepath.Join(tempDir, ".gitignore")
	err := os.WriteFile(filePath, []byte(ignorePatterns), 0600)
	if err != nil {
		t.Fatal(t, err, "Couldn't write .gitignore")
	}
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
func TestIsSastEnabled(t *testing.T) {
	apiClient := &snyk_api.FakeApiClient{
		CodeEnabled: false,
		ApiError:    nil,
	}
	scanner := &Scanner{
		SnykApiClient: apiClient,
	}
	t.Run("should return false if Snyk Code is disabled", func(t *testing.T) {
		config.CurrentConfig().SetSnykCodeEnabled(false)
		enabled := scanner.isSastEnabled()
		assert.False(t, enabled)
	})

	t.Run("should call the API to check enablement if Snyk Code is enabled", func(t *testing.T) {
		config.CurrentConfig().SetSnykCodeEnabled(true)
		scanner.isSastEnabled()
		assert.Equal(t, 1, len(apiClient.Calls))
	})

	t.Run("should return true if Snyk Code is enabled and the API returns true", func(t *testing.T) {
		config.CurrentConfig().SetSnykCodeEnabled(true)
		apiClient.CodeEnabled = true
		enabled := scanner.isSastEnabled()
		assert.True(t, enabled)
	})

	t.Run("should return false if Snyk Code is enabled and the API returns false", func(t *testing.T) {
		config.CurrentConfig().SetSnykCodeEnabled(true)
		apiClient.CodeEnabled = false
		enabled := scanner.isSastEnabled()
		assert.False(t, enabled)
	})

	t.Run("should return false if Snyk Code is enabled and the API returns an error", func(t *testing.T) {
		config.CurrentConfig().SetSnykCodeEnabled(true)
		apiClient.CodeEnabled = false
		apiClient.ApiError = &snyk_api.SnykApiError{}
		enabled := scanner.isSastEnabled()
		assert.False(t, enabled)
	})

	t.Run("should send a ShowMessageRequest notification if Snyk Code is enabled and the API returns false",
		func(t *testing.T) {
			notification.DisposeListener()
			config.CurrentConfig().SetSnykCodeEnabled(true)
			apiClient.CodeEnabled = false
			actionMap := data_structure.NewOrderedMap[snyk.MessageAction, snyk.CommandInterface]()

			actionMap.Add(enableSnykCodeMessageActionItemTitle, command.NewOpenBrowserCommand(getCodeEnablementUrl()))
			actionMap.Add(closeMessageActionItemTitle, nil)
			expectedShowMessageRequest := snyk.ShowMessageRequest{
				Message: codeDisabledInOrganisationMessageText,
				Type:    snyk.Warning,
				Actions: actionMap,
			}

			channel := make(chan any)

			notification.CreateListener(func(params any) {
				channel <- params
			})
			defer notification.DisposeListener()

			scanner.isSastEnabled()

			assert.Equal(t, expectedShowMessageRequest, <-channel)
		})
}
