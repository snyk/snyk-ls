/*
 * © 2022-2024 Snyk Limited
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

	"github.com/erni27/imcache"
	"github.com/golang/mock/gomock"
	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/learn/mock_learn"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
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
				sliceToChannel([]string{file}),
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
				sliceToChannel([]string{file}),
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
				sliceToChannel([]string{file}),
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
				sliceToChannel([]string{file}),
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
			NewBundler(snykCodeMock, NewCodeInstrumentor()),
			&snyk_api.FakeApiClient{CodeEnabled: true},
			newTestCodeErrorReporter(),
			ux2.NewTestAnalytics(),
			nil,
			notification.NewNotifier(),
			&FakeCodeScannerClient{},
		)
		tempDir := t.TempDir()
		file := filepath.Join(tempDir, configFile)
		err := os.WriteFile(file, []byte("some content so the file won't be skipped"), 0600)
		assert.Nil(t, err)

		bundle, err := scanner.createBundle(context.Background(),
			"testRequestId",
			tempDir,
			sliceToChannel([]string{file}),
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

		_, scanner := setupTestScanner(t)
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
			sliceToChannel(filesFullPaths),
			map[string]bool{})

		// Assert
		assert.Nil(t, err)
		for _, expectedPath := range expectedPaths {
			assert.Contains(t, bundle.Files, expectedPath)
		}
	})
}

func sliceToChannel(slice []string) <-chan string {
	ch := make(chan string)
	go func() {
		defer close(ch)
		for _, s := range slice {
			ch <- s
		}
	}()

	return ch
}

func setupCreateBundleTest(t *testing.T, extension string) (*FakeSnykCodeClient, string, *Scanner, string) {
	t.Helper()
	testutil.UnitTest(t)
	dir := t.TempDir()
	snykCodeMock, c := setupTestScanner(t)
	file := filepath.Join(dir, "file."+extension)
	return snykCodeMock, dir, c, file
}

func setupTestScanner(t *testing.T) (*FakeSnykCodeClient, *Scanner) {
	t.Helper()
	snykCodeMock := &FakeSnykCodeClient{}
	learnMock := mock_learn.NewMockService(gomock.NewController(t))
	learnMock.
		EXPECT().
		GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&learn.Lesson{}, nil).AnyTimes()
	scanner := New(
		NewBundler(snykCodeMock, NewCodeInstrumentor()),
		&snyk_api.FakeApiClient{CodeEnabled: true},
		newTestCodeErrorReporter(),
		ux2.NewTestAnalytics(),
		learnMock,
		notification.NewNotifier(),
		&FakeCodeScannerClient{},
	)

	return snykCodeMock, scanner
}

func TestUploadAndAnalyze(t *testing.T) {
	learnMock := mock_learn.NewMockService(gomock.NewController(t))
	learnMock.
		EXPECT().
		GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&learn.Lesson{}, nil).AnyTimes()
	t.Run(
		"should create bundle when hash empty", func(t *testing.T) {
			testutil.UnitTest(t)
			snykCodeMock := &FakeSnykCodeClient{}
			c := New(
				NewBundler(snykCodeMock, NewCodeInstrumentor()),
				&snyk_api.FakeApiClient{CodeEnabled: true},
				newTestCodeErrorReporter(),
				ux2.NewTestAnalytics(),
				learnMock,
				notification.NewNotifier(),
				&FakeCodeScannerClient{},
			)
			baseDir, firstDoc, _, content1, _ := setupDocs(t)
			fullPath := uri.PathFromUri(firstDoc.URI)
			docs := sliceToChannel([]string{fullPath})
			metrics := c.newMetrics(time.Time{})

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
				NewBundler(snykCodeMock, NewCodeInstrumentor()),
				&snyk_api.FakeApiClient{CodeEnabled: true},
				newTestCodeErrorReporter(),
				ux2.NewTestAnalytics(),
				learnMock,
				notification.NewNotifier(),
				&FakeCodeScannerClient{},
			)
			filePath, path := TempWorkdirWithVulnerabilities(t)
			defer func(path string) { _ = os.RemoveAll(path) }(path)
			files := []string{filePath}
			metrics := c.newMetrics(time.Time{})

			issues, _ := c.UploadAndAnalyze(context.Background(), sliceToChannel(files), path, metrics, map[string]bool{})

			assert.NotNil(t, issues)
			assert.Equal(t, 1, len(issues))

			assert.Equal(t, FakeIssue.ID, issues[0].ID)
			assert.Equal(t, FakeIssue.Range, issues[0].Range)
			assert.Equal(t, FakeIssue.Message, issues[0].Message)
			assert.Equal(t, len(FakeIssue.CodelensCommands), len(issues[0].CodelensCommands))
			assert.GreaterOrEqual(t, len(issues[0].CodeActions), len(FakeIssue.CodeActions)) // Some codeactions are added by the scanner (e.g. Autofix, Snyk Learn)

			// verify that extend bundle has been called on backend service with additional file
			params := snykCodeMock.GetCallParams(0, RunAnalysisOperation)
			assert.NotNil(t, params)
			assert.Equal(t, 3, len(params))
			assert.Equal(t, 0, params[2])

			// verify that bundle hash has been saved
			assert.Equal(t, 1, len(c.BundleHashes))
			assert.Equal(t, snykCodeMock.Options.bundleHash, c.BundleHashes[path])
		},
	)

	t.Run(
		"should track analytics", func(t *testing.T) {
			testutil.UnitTest(t)
			snykCodeMock := &FakeSnykCodeClient{}
			analytics := ux2.NewTestAnalytics()
			c := New(
				NewBundler(snykCodeMock, NewCodeInstrumentor()),
				&snyk_api.FakeApiClient{CodeEnabled: true},
				newTestCodeErrorReporter(),
				analytics,
				learnMock,
				notification.NewNotifier(),
				&FakeCodeScannerClient{},
			)
			diagnosticUri, path := TempWorkdirWithVulnerabilities(t)
			defer func(path string) { _ = os.RemoveAll(path) }(path)
			files := []string{diagnosticUri}
			metrics := c.newMetrics(time.Now())

			// execute
			_, _ = c.UploadAndAnalyze(context.Background(), sliceToChannel(files), "", metrics, map[string]bool{})

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

func TestUploadAndAnalyzeWithIgnores(t *testing.T) {
	learnMock := mock_learn.NewMockService(gomock.NewController(t))
	learnMock.
		EXPECT().
		GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&learn.Lesson{}, nil).AnyTimes()
	testutil.UnitTest(t)
	snykCodeMock := &FakeSnykCodeClient{}

	diagnosticUri, path := TempWorkdirWithVulnerabilities(t)
	defer func(path string) { _ = os.RemoveAll(path) }(path)
	files := []string{diagnosticUri}
	fakeCodeScanner := &FakeCodeScannerClient{rootPath: diagnosticUri}

	c := New(
		NewBundler(snykCodeMock, NewCodeInstrumentor()),
		&snyk_api.FakeApiClient{CodeEnabled: true},
		newTestCodeErrorReporter(),
		ux2.NewTestAnalytics(),
		learnMock,
		notification.NewNotifier(),
		fakeCodeScanner,
	)
	issues, _ := c.UploadAndAnalyzeWithIgnores(context.Background(), "", sliceToChannel(files), map[string]bool{})
	assert.True(t, fakeCodeScanner.UploadAndAnalyzeWasCalled)
	assert.False(t, issues[0].IsIgnored)
	assert.Nil(t, issues[0].IgnoreDetails)
	assert.Equal(t, true, issues[1].IsIgnored)
	assert.Equal(t, "wont-fix", issues[1].IgnoreDetails.Category)
	assert.Equal(t, "False positive", issues[1].IgnoreDetails.Reason)
	assert.Equal(t, "13 days", issues[1].IgnoreDetails.Expiration)
	assert.Equal(t, 2024, issues[1].IgnoreDetails.IgnoredOn.Year())
	assert.Equal(t, "Neil M", issues[1].IgnoreDetails.IgnoredBy)
}

func Test_Scan(t *testing.T) {
	t.Run("Should update changed files", func(t *testing.T) {
		testutil.UnitTest(t)
		// Arrange
		snykCodeMock, scanner := setupTestScanner(t)
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
		_, scanner := setupTestScanner(t)
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
		snykCodeMock, scanner := setupTestScanner(t)

		tempDir, _, _ := setupIgnoreWorkspace(t)

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
		tempDir, _, _ := setupIgnoreWorkspace(t)
		fakeClient, scanner := setupTestScanner(t)
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
		tempDir, _, _ := setupIgnoreWorkspace(t)
		tempDir2, _, _ := setupIgnoreWorkspace(t)
		fakeClient, scanner := setupTestScanner(t)
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
			NewBundler(snykCodeMock, NewCodeInstrumentor()),
			&snyk_api.FakeApiClient{CodeEnabled: false},
			newTestCodeErrorReporter(),
			ux2.NewTestAnalytics(),
			nil,
			notification.NewNotifier(),
			&FakeCodeScannerClient{},
		)
		tempDir, _, _ := setupIgnoreWorkspace(t)

		_, _ = c.Scan(context.Background(), "", tempDir)

		params := snykCodeMock.GetCallParams(0, CreateBundleOperation)
		assert.Nil(t, params)
	})

	//nolint:dupl // test cases differ by a boolean
	t.Run("Should run existing flow if feature flag is disabled", func(t *testing.T) {
		testutil.UnitTest(t)
		snykCodeMock := &FakeSnykCodeClient{}
		snykApiMock := &snyk_api.FakeApiClient{CodeEnabled: true}
		snykApiMock.SetResponse("FeatureFlagStatus", snyk_api.FFResponse{Ok: false})
		learnMock := mock_learn.NewMockService(gomock.NewController(t))
		learnMock.
			EXPECT().
			GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&learn.Lesson{}, nil).AnyTimes()

		c := New(
			NewBundler(snykCodeMock, NewCodeInstrumentor()),
			snykApiMock,
			newTestCodeErrorReporter(),
			ux2.NewTestAnalytics(),
			learnMock,
			notification.NewNotifier(),
			&FakeCodeScannerClient{},
		)
		tempDir, _, _ := setupIgnoreWorkspace(t)

		_, _ = c.Scan(context.Background(), "", tempDir)

		params := snykCodeMock.GetCallParams(0, CreateBundleOperation)
		assert.NotNil(t, params)
	})

	//nolint:dupl // test cases differ by a boolean
	t.Run("Should run new flow if feature flag is enabled", func(t *testing.T) {
		testutil.UnitTest(t)
		snykCodeMock := &FakeSnykCodeClient{}
		snykApiMock := &snyk_api.FakeApiClient{CodeEnabled: true}
		snykApiMock.SetResponse("FeatureFlagStatus", snyk_api.FFResponse{Ok: true})
		learnMock := mock_learn.NewMockService(gomock.NewController(t))
		learnMock.
			EXPECT().
			GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&learn.Lesson{}, nil).AnyTimes()

		c := New(
			NewBundler(snykCodeMock, NewCodeInstrumentor()),
			snykApiMock,
			newTestCodeErrorReporter(),
			ux2.NewTestAnalytics(),
			learnMock,
			notification.NewNotifier(),
			&FakeCodeScannerClient{},
		)
		tempDir, _, _ := setupIgnoreWorkspace(t)

		_, _ = c.Scan(context.Background(), "", tempDir)

		params := snykCodeMock.GetCallParams(0, CreateBundleOperation)
		assert.Nil(t, params)
	})
}

func setupIgnoreWorkspace(t *testing.T) (tempDir string, ignoredFilePath string, notIgnoredFilePath string) {
	t.Helper()
	expectedPatterns := "*.xml\n**/*.txt\nbin"
	tempDir = writeTestGitIgnore(t, expectedPatterns)

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

	return tempDir, ignoredFilePath, notIgnoredFilePath
}

func writeTestGitIgnore(t *testing.T, ignorePatterns string) (tempDir string) {
	t.Helper()
	tempDir = t.TempDir()
	writeGitIgnoreIntoDir(t, ignorePatterns, tempDir)
	return tempDir
}

func writeGitIgnoreIntoDir(t *testing.T, ignorePatterns string, tempDir string) {
	t.Helper()
	filePath := filepath.Join(tempDir, ".gitignore")
	err := os.WriteFile(filePath, []byte(ignorePatterns), 0600)
	if err != nil {
		t.Fatal(t, err, "Couldn't write .gitignore")
	}
}

func Test_IsEnabled(t *testing.T) {
	scanner := &Scanner{errorReporter: newTestCodeErrorReporter()}
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

func autofixSetupAndCleanup(t *testing.T) {
	t.Helper()
	resetCodeSettings()
	t.Cleanup(resetCodeSettings)
	config.CurrentConfig().SetSnykCodeEnabled(true)
	getCodeSettings().isAutofixEnabled.Set(false)
}

func TestUploadAnalyzeWithAutofix(t *testing.T) {
	learnMock := mock_learn.NewMockService(gomock.NewController(t))
	learnMock.
		EXPECT().
		GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&learn.Lesson{}, nil).AnyTimes()

	t.Run(
		"should not add autofix after analysis when not enabled", func(t *testing.T) {
			testutil.UnitTest(t)
			autofixSetupAndCleanup(t)

			snykCodeMock := &FakeSnykCodeClient{}
			analytics := ux2.NewTestAnalytics()
			c := New(
				NewBundler(snykCodeMock, NewCodeInstrumentor()),
				&snyk_api.FakeApiClient{CodeEnabled: true},
				newTestCodeErrorReporter(),
				analytics,
				learnMock,
				notification.NewNotifier(),
				&FakeCodeScannerClient{},
			)
			diagnosticUri, path := TempWorkdirWithVulnerabilities(t)
			t.Cleanup(
				func() {
					_ = os.RemoveAll(path)
				},
			)
			files := []string{diagnosticUri}
			metrics := c.newMetrics(time.Now())

			// execute
			issues, _ := c.UploadAndAnalyze(context.Background(), sliceToChannel(files), "", metrics, map[string]bool{})

			assert.Len(t, analytics.GetAnalytics(), 1)
			// Default is to have 1 fake action from analysis + 0 from autofix
			assert.Len(t, issues[0].CodeActions, 1)
		},
	)

	t.Run(
		"should not provide autofix code action when autofix enabled but issue not fixable",
		func(t *testing.T) {
			testutil.UnitTest(t)
			autofixSetupAndCleanup(t)
			getCodeSettings().isAutofixEnabled.Set(true)

			snykCodeMock := &FakeSnykCodeClient{}
			snykCodeMock.NoFixSuggestions = true

			analytics := ux2.NewTestAnalytics()
			c := New(
				NewBundler(snykCodeMock, NewCodeInstrumentor()),
				&snyk_api.FakeApiClient{CodeEnabled: true},
				newTestCodeErrorReporter(),
				analytics,
				learnMock,
				notification.NewNotifier(),
				&FakeCodeScannerClient{},
			)
			diagnosticUri, path := TempWorkdirWithVulnerabilities(t)
			t.Cleanup(
				func() {
					_ = os.RemoveAll(path)
				},
			)
			files := []string{diagnosticUri}
			metrics := c.newMetrics(time.Now())

			// execute
			issues, _ := c.UploadAndAnalyze(context.Background(), sliceToChannel(files), "", metrics, map[string]bool{})

			assert.Len(t, analytics.GetAnalytics(), 1)
			// Default is to have 1 fake action from analysis + 0 from autofix
			assert.Len(t, issues[0].CodeActions, 1)
		},
	)

	t.Run(
		"should run autofix after analysis when is enabled", func(t *testing.T) {
			testutil.UnitTest(t)
			autofixSetupAndCleanup(t)
			getCodeSettings().isAutofixEnabled.Set(true)

			snykCodeMock := &FakeSnykCodeClient{}
			analytics := ux2.NewTestAnalytics()
			c := New(
				NewBundler(snykCodeMock, NewCodeInstrumentor()),
				&snyk_api.FakeApiClient{CodeEnabled: true},
				newTestCodeErrorReporter(),
				analytics,
				learnMock,
				notification.NewNotifier(),
				&FakeCodeScannerClient{},
			)
			diagnosticUri, path := TempWorkdirWithVulnerabilities(t)
			t.Cleanup(
				func() {
					_ = os.RemoveAll(path)
				},
			)
			files := []string{diagnosticUri}
			metrics := c.newMetrics(time.Now())

			// execute
			issues, _ := c.UploadAndAnalyze(context.Background(), sliceToChannel(files), "", metrics, map[string]bool{})

			assert.Len(t, analytics.GetAnalytics(), 1)
			assert.Len(t, issues[0].CodeActions, 2)
			val, ok := (*issues[0].CodeActions[1].DeferredEdit)().Changes[EncodePath(issues[0].AffectedFilePath)]
			assert.True(t, ok)
			// If this fails, likely the format of autofix edits has changed to
			// "hunk-like" ones rather than replacing the whole file
			assert.Len(t, val, 1)
			// Checks that it arrived from fake autofix indeed.
			assert.Equal(t, val[0].NewText, FakeAutofixSuggestionNewText)
		},
	)
}

func Test_SastApiCall(t *testing.T) {
	apiClient := &snyk_api.FakeApiClient{
		CodeEnabled: false,
		ApiError:    nil,
	}

	scanner := &Scanner{
		SnykApiClient: apiClient,
		errorReporter: newTestCodeErrorReporter(),
		notifier:      notification.NewNotifier(),
	}

	t.Run("should call the API to check enablement if Snyk Code is enabled", func(t *testing.T) {
		apiClient.ApiError = nil
		config.CurrentConfig().SetSnykCodeEnabled(true)

		_, _ = scanner.Scan(context.Background(), "fileName", "tempDir")

		assert.Equal(t, 1, len(apiClient.Calls))
	})

	t.Run("should return an error if Snyk Code is enabled and the API returns an error", func(t *testing.T) {
		config.CurrentConfig().SetSnykCodeEnabled(true)
		apiClient.ApiError = &snyk_api.SnykApiError{}
		_, err := scanner.Scan(context.Background(), "fileName", "tempDir")

		assert.Error(t, err)
		assert.Equal(t, err.Error(), "couldn't get sast enablement")
	})

	t.Run("should return an error if Snyk Code is enabled and API SAST is disabled", func(t *testing.T) {
		config.CurrentConfig().SetSnykCodeEnabled(true)
		apiClient.ApiError = nil
		apiClient.CodeEnabled = false
		_, err := scanner.Scan(context.Background(), "fileName", "tempDir")

		assert.Error(t, err)
		assert.Equal(t, err.Error(), "SAST is not enabled")
	})

	t.Run("should return an error if API SAST is disabled and local-engine is enabled", func(t *testing.T) {
		config.CurrentConfig().SetSnykCodeEnabled(true)
		apiClient.ApiError = nil
		apiClient.CodeEnabled = false
		apiClient.LocalCodeEngine.Enabled = true
		_, err := scanner.Scan(context.Background(), "fileName", "tempDir")

		assert.Error(t, err)
		assert.Equal(t, err.Error(), "SAST is not enabled")
	})
}

func TestScanner_getFilesToBeScanned(t *testing.T) {
	config.CurrentConfig().SetSnykCodeEnabled(true)
	_, scanner := setupTestScanner(t)
	tempDir := t.TempDir()
	scanner.changedPaths = make(map[string]map[string]bool)
	scanner.changedPaths[tempDir] = make(map[string]bool)

	t.Run("should add all files from changedPaths map and delete them from changedPaths", func(t *testing.T) {
		changedFile := "file1.java"
		scanner.changedPaths[tempDir][changedFile] = true
		scanner.changedPaths[tempDir]["file2.java"] = true

		files := scanner.getFilesToBeScanned(tempDir)

		require.Contains(t, files, changedFile)
		require.Contains(t, files, "file2.java")
		require.Len(t, scanner.changedPaths[tempDir], 0)
	})

	t.Run("should add all files that have dataflow items of a changed file", func(t *testing.T) {
		changedFile := "main.ts"
		fromChangeAffectedFile := "juice-shop/routes/vulnCodeSnippet.ts"

		// we need to add a fake issue to the cache, let's keep it to the minimum needed
		// we are reusing the test data from the code_html test
		codeIssueData := snyk.CodeIssueData{
			DataFlow: getDataFlowElements(),
		}

		// add the changed file to the changed paths store
		scanner.changedPaths[tempDir][changedFile] = true

		// add the issue. The issue references `changedFile` in the dataflow
		issue := snyk.Issue{AdditionalData: codeIssueData}
		scanner.issueCache.Set(fromChangeAffectedFile, []snyk.Issue{issue}, imcache.WithDefaultExpiration())
		defer scanner.issueCache.RemoveAll()

		files := scanner.getFilesToBeScanned(tempDir)

		// The `changedFile` is automatically scanned, but it is mentioned by `fromChangeAffectedFile` in the dataflow
		// Thus, now we should have both files
		require.Contains(t, files, changedFile)
		require.Contains(t, files, fromChangeAffectedFile)
	})
}

func TestScanner_Cache(t *testing.T) {
	_, scanner := setupTestScanner(t)
	t.Run("should add issues to the cache", func(t *testing.T) {
		scanner.addToCache([]snyk.Issue{{ID: "issue1", AffectedFilePath: "file1.java"}})
		scanner.addToCache([]snyk.Issue{{ID: "issue2", AffectedFilePath: "file2.java"}})

		_, added := scanner.issueCache.Get("file1.java")
		require.True(t, added)
		_, added = scanner.issueCache.Get("file2.java")
		require.True(t, added)
	})
	t.Run("should automatically expire entries after a time", func(t *testing.T) {
		scanner.issueCache = imcache.New[string, []snyk.Issue](
			imcache.WithDefaultExpirationOption[string, []snyk.Issue](time.Microsecond),
		)
		issue := snyk.Issue{ID: "issue1", AffectedFilePath: "file1.java"}
		scanner.addToCache([]snyk.Issue{issue})

		time.Sleep(time.Millisecond)
		_, found := scanner.issueCache.Get("file1.java")
		require.False(t, found)
	})
	t.Run("should add scan results to cache", func(t *testing.T) {
		scanner.issueCache.RemoveAll()
		scanner.issueCache.Set("file2.java", []snyk.Issue{{ID: "issue2"}}, imcache.WithDefaultExpiration())
		filePath, folderPath := TempWorkdirWithVulnerabilities(t)

		_, err := scanner.Scan(context.Background(), filePath, folderPath)
		require.NoError(t, err)

		issue := scanner.Issue(FakeIssue.AdditionalData.GetKey())
		require.NotNil(t, issue)
	})
}

func TestScanner_IssueProvider(t *testing.T) {
	t.Run("should find issue by key", func(t *testing.T) {
		_, scanner := setupTestScanner(t)
		issue := snyk.Issue{ID: "issue1", AffectedFilePath: "file1.java", AdditionalData: &snyk.CodeIssueData{Key: "key"}}
		scanner.addToCache([]snyk.Issue{issue})

		foundIssue := scanner.Issue("key")
		require.Equal(t, issue, foundIssue)
	})

	t.Run("should find issue by path and range", func(t *testing.T) {
		_, scanner := setupTestScanner(t)
		issue := snyk.Issue{ID: "issue1", AffectedFilePath: "file1.java", AdditionalData: &snyk.CodeIssueData{Key: "key"}}
		scanner.addToCache([]snyk.Issue{issue})

		foundIssues := scanner.IssuesFor("file1.java", issue.Range)
		require.Contains(t, foundIssues, issue)
	})
	t.Run("should not find issue by path when range does not overlap", func(t *testing.T) {
		_, scanner := setupTestScanner(t)
		issue := snyk.Issue{ID: "issue1", AffectedFilePath: "file1.java", AdditionalData: &snyk.CodeIssueData{Key: "key"}}
		scanner.addToCache([]snyk.Issue{issue})

		foundIssues := scanner.IssuesFor(
			"file1.java",
			snyk.Range{
				Start: snyk.Position{Line: 3},
				End:   snyk.Position{Line: 4},
			},
		)
		require.NotContains(t, foundIssues, issue)
	})
}
