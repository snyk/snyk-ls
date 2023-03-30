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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

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
func setupDocs(t *testing.T) (string, lsp.TextDocumentItem, lsp.TextDocumentItem, []byte, []byte) {
	t.Helper()
	path := t.TempDir()

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
			bundle, err := c.createBundle(context.Background(),
				"testRequestId",
				dir,
				[]string{file},
				map[string]bool{})
			if err != nil {
				t.Fatal(err)
			}
			bundleFiles := bundle.Files
			assert.Len(t, bundleFiles, 1, "bundle should have 1 bundle files")
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
			bundle, err := c.createBundle(context.Background(),
				"testRequestId",
				dir,
				[]string{file},
				map[string]bool{})
			if err != nil {
				t.Fatal(err)
			}
			bundleFiles := bundle.Files
			assert.Len(t, bundleFiles, 0, "bundle should not have bundle files")
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
			bundle, err := c.createBundle(context.Background(),
				"testRequestId",
				dir,
				[]string{file},
				map[string]bool{})
			if err != nil {
				t.Fatal(err)
			}

			bundleFiles := bundle.Files
			assert.Len(t, bundleFiles, 0, "bundle should not have bundle files")
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
			bundle, err := c.createBundle(context.Background(),
				"testRequestId",
				dir,
				[]string{file},
				map[string]bool{})
			bundleFiles := bundle.Files
			if err != nil {
				t.Fatal(err)
			}
			assert.Len(t, bundleFiles, 0, "bundle should not have bundle files")
			assert.Len(t, snykCodeMock.GetAllCalls(CreateBundleOperation), 0, "bundle shouldn't have called createBundle")
		},
	)

	t.Run("includes config files", func(t *testing.T) {
		configFile := ".test"
		snykCodeMock := &FakeSnykCodeClient{
			ConfigFiles: []string{configFile},
		}
		scanner := New(
			NewBundler(snykCodeMock, performance.NewTestInstrumentor()),
			&snyk_api.FakeApiClient{CodeEnabled: true},
			error_reporting.NewTestErrorReporter(),
			ux2.NewTestAnalytics(),
		)
		tempDir := t.TempDir()
		file := filepath.Join(tempDir, configFile)
		err := os.WriteFile(file, []byte("some content so the file won't be skipped"), 0600)
		assert.Nil(t, err)

		bundle, err := scanner.createBundle(context.Background(),
			"testRequestId",
			tempDir,
			[]string{file},
			map[string]bool{})
		assert.Nil(t, err)
		relativePath, _ := ToRelativeUnixPath(tempDir, file)
		assert.Contains(t, bundle.Files, relativePath)
	})
	t.Run("url-encodes files", func(t *testing.T) {
		// Arrange
		filesRelPaths := []string{
			"path/to/file1.java",
			"path/with spaces/file2.java",
		}
		expectedPaths := []string{
			"path/to/file1.java",
			"path/with%20spaces/file2.java",
		}

		_, scanner := setupTestScanner()
		tempDir := t.TempDir()
		var filesFullPaths []string
		for _, fileRelPath := range filesRelPaths {
			file := filepath.Join(tempDir, fileRelPath)
			filesFullPaths = append(filesFullPaths, file)
			_ = os.MkdirAll(filepath.Dir(file), 0700)
			err := os.WriteFile(file, []byte("some content so the file won't be skipped"), 0600)
			assert.Nil(t, err)
		}

		bundle, err := scanner.createBundle(context.Background(),
			"testRequestId",
			tempDir,
			filesFullPaths,
			map[string]bool{})

		// Assert
		assert.Nil(t, err)
		for _, expectedPath := range expectedPaths {
			assert.Contains(t, bundle.Files, expectedPath)
		}
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
			baseDir, firstDoc, _, content1, _ := setupDocs(t)
			fullPath := uri.PathFromUri(firstDoc.URI)
			docs := []string{fullPath}
			metrics := c.newMetrics(len(docs), time.Time{})

			_, _ = c.UploadAndAnalyze(context.Background(), docs, baseDir, metrics, map[string]bool{})

			// verify that create bundle has been called on backend service
			params := snykCodeMock.GetCallParams(0, CreateBundleOperation)
			assert.NotNil(t, params)
			assert.Equal(t, 1, len(params))
			files := params[0].(map[string]string)
			relPath, err := ToRelativeUnixPath(baseDir, fullPath)
			assert.Nil(t, err)
			assert.Equal(t, files[relPath], util.Hash(content1))
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

			issues, _ := c.UploadAndAnalyze(context.Background(), files, "", metrics, map[string]bool{})

			assert.NotNil(t, issues)
			assert.Equal(t, 1, len(issues))
			assert.Equal(t, FakeIssue, issues[0])

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
			_, _ = c.UploadAndAnalyze(context.Background(), files, "", metrics, map[string]bool{})

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

func Test_Scan(t *testing.T) {
	t.Run("Should update changed files", func(t *testing.T) {
		testutil.UnitTest(t)
		// Arrange
		snykCodeMock, scanner := setupTestScanner()
		wg := sync.WaitGroup{}
		changedFilesRelPaths := []string{ // File paths relative to the repo base
			"file0.go",
			"file1.go",
			"file2.go",
			"someDir/nested.go",
		}
		fileCount := len(changedFilesRelPaths)
		tempDir := t.TempDir()
		var changedFilesAbsPaths []string
		for _, file := range changedFilesRelPaths {
			fullPath := filepath.Join(tempDir, file)
			err := os.MkdirAll(filepath.Dir(fullPath), 0755)
			assert.Nil(t, err)
			err = os.WriteFile(fullPath, []byte("func main() {}"), 0644)
			assert.Nil(t, err)
			changedFilesAbsPaths = append(changedFilesAbsPaths, fullPath)
		}

		// Act
		for _, fileName := range changedFilesAbsPaths {
			wg.Add(1)
			go func(fileName string) {
				t.Log("Running scan for file " + fileName)
				_, _ = scanner.Scan(context.Background(), fileName, tempDir)
				t.Log("Finished scan for file " + fileName)
				wg.Done()
			}(fileName)
		}
		wg.Wait()

		// Assert
		allCalls := snykCodeMock.GetAllCalls(RunAnalysisOperation)
		communicatedChangedFiles := make([]string, 0)
		for _, call := range allCalls {
			params := call[1].([]string)
			communicatedChangedFiles = append(communicatedChangedFiles, params...)
		}

		assert.Equal(t, fileCount, len(communicatedChangedFiles))
		for _, file := range changedFilesRelPaths {
			assert.Contains(t, communicatedChangedFiles, file)
		}
	})

	t.Run("Should reset changed files after successful scan", func(t *testing.T) {
		testutil.UnitTest(t)
		// Arrange
		_, scanner := setupTestScanner()
		wg := sync.WaitGroup{}
		tempDir := t.TempDir()

		// Act
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func(i int) {
				_, _ = scanner.Scan(context.Background(), "file"+strconv.Itoa(i)+".go", tempDir)
				wg.Done()
			}(i)
		}
		wg.Wait()

		// Assert
		assert.Equal(t, 0, len(scanner.changedPaths[tempDir]))
	})

	t.Run("Should not mark folders as changed files", func(t *testing.T) {
		testutil.UnitTest(t)
		// Arrange
		snykCodeMock, scanner := setupTestScanner()

		_, tempDir, _, _, _ := setupIgnoreWorkspace(t)

		// Act
		_, _ = scanner.Scan(context.Background(), tempDir, tempDir)

		// Assert
		params := snykCodeMock.GetCallParams(0, RunAnalysisOperation)
		assert.NotNil(t, params)
		assert.Equal(t, 0, len(params[1].([]string)))
	})

	t.Run("Scans run sequentially for the same folder", func(t *testing.T) {
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
	})

	t.Run("Scans run in parallel for different folders", func(t *testing.T) {
		// Arrange
		testutil.UnitTest(t)
		_, tempDir, _, _, _ := setupIgnoreWorkspace(t)
		_, tempDir2, _, _, _ := setupIgnoreWorkspace(t)
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
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				_, _ = scanner.Scan(context.Background(), "", tempDir2)
				wg.Done()
			}()
		}
		wg.Wait()

		// Assert
		assert.Equal(t, 2, fakeClient.maxConcurrentScans)
	})

	t.Run("Shouldn't run if Sast is disabled", func(t *testing.T) {
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
	})
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

func autofixSetupAndCleanup(t *testing.T) {
	t.Cleanup(resetCodeSettings)
	config.CurrentConfig().SetSnykCodeEnabled(true)
	getCodeSettings().isAutofixEnabled.Set(false)
}

func TestUploadAnalyzeWithAutofix(t *testing.T) {
	autofixSetupAndCleanup(t)
	t.Run(
		"should not add autofix after analysis when not enabled", func(t *testing.T) {
			testutil.UnitTest(t)
			config.CurrentConfig().SetSnykCodeEnabled(true)

			snykCodeMock := &FakeSnykCodeClient{}
			analytics := ux2.NewTestAnalytics()
			c := New(
				NewBundler(snykCodeMock, performance.NewTestInstrumentor()),
				&snyk_api.FakeApiClient{CodeEnabled: true},
				error_reporting.NewTestErrorReporter(),
				analytics,
			)
			diagnosticUri, path := TempWorkdirWithVulnerabilities(t)
			t.Cleanup(
				func() {
					_ = os.RemoveAll(path)
				},
			)
			files := []string{diagnosticUri}
			metrics := c.newMetrics(len(files), time.Now())

			// execute
			issues, _ := c.UploadAndAnalyze(context.Background(), files, "", metrics, map[string]bool{})

			assert.Len(t, analytics.GetAnalytics(), 1)
			// Default is to have 1 fake action from analysis + 0 from autofix
			assert.Len(t, issues[0].CodeActions, 1)
		},
	)

	t.Run(
		"should run autofix after analysis when is enabled", func(t *testing.T) {
			testutil.UnitTest(t)
			config.CurrentConfig().SetSnykCodeEnabled(true)
			getCodeSettings().isAutofixEnabled.Set(true)

			snykCodeMock := &FakeSnykCodeClient{}
			analytics := ux2.NewTestAnalytics()
			c := New(
				NewBundler(snykCodeMock, performance.NewTestInstrumentor()),
				&snyk_api.FakeApiClient{CodeEnabled: true},
				error_reporting.NewTestErrorReporter(),
				analytics,
			)
			diagnosticUri, path := TempWorkdirWithVulnerabilities(t)
			t.Cleanup(
				func() {
					_ = os.RemoveAll(path)
				},
			)
			files := []string{diagnosticUri}
			metrics := c.newMetrics(len(files), time.Now())

			// execute
			issues, _ := c.UploadAndAnalyze(context.Background(), files, "", metrics, map[string]bool{})

			assert.Len(t, analytics.GetAnalytics(), 1)
			assert.Len(t, issues[0].CodeActions, 2)
			val, ok := (*issues[0].CodeActions[1].DeferredEdit)().Changes[FakeAutofixFileUri]
			assert.True(t, ok)
			// If this fails, likely the format of autofix edits has changed to
			// "hunk-like" ones rather than replacing the whole file
			assert.Len(t, val, 1)
			// Checks that it arrived from fake autofix indeed.
			assert.Equal(t, val[0].NewText, FakeAutofixSuggestionNewText)
		},
	)
}
