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

	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/vcs"

	"github.com/erni27/imcache"
	"github.com/golang/mock/gomock"
	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
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
	c := testutil.UnitTest(t)
	channel := make(chan types.ProgressParams, 10000)
	cancelChannel := make(chan bool, 1)
	testTracker := progress.NewTestTracker(channel, cancelChannel)

	t.Run(
		"when < maxFileSize creates bundle", func(t *testing.T) {
			snykCodeMock, dir, c, file := setupCreateBundleTest(t, "java")
			data := strings.Repeat("a", maxFileSize-10)
			err := os.WriteFile(file, []byte(data), 0600)

			if err != nil {
				t.Fatal(err)
			}
			bundle, err := c.createBundle(context.Background(), "testRequestId", dir, sliceToChannel([]string{file}), map[string]bool{}, testTracker)
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
			bundle, err := c.createBundle(context.Background(), "testRequestId", dir, sliceToChannel([]string{file}), map[string]bool{}, testTracker)
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
			bundle, err := c.createBundle(context.Background(), "testRequestId", dir, sliceToChannel([]string{file}), map[string]bool{}, testTracker)
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
			bundle, err := c.createBundle(context.Background(), "testRequestId", dir, sliceToChannel([]string{file}), map[string]bool{}, testTracker)
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
		scanner := New(NewBundler(c, snykCodeMock, NewCodeInstrumentor()), &snyk_api.FakeApiClient{CodeEnabled: true}, newTestCodeErrorReporter(), nil, notification.NewNotifier(), &FakeCodeScannerClient{})
		tempDir := t.TempDir()
		file := filepath.Join(tempDir, configFile)
		err := os.WriteFile(file, []byte("some content so the file won't be skipped"), 0600)
		assert.Nil(t, err)

		bundle, err := scanner.createBundle(context.Background(), "testRequestId", tempDir, sliceToChannel([]string{file}), map[string]bool{}, testTracker)
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

		bundle, err := scanner.createBundle(context.Background(), "testRequestId", tempDir, sliceToChannel(filesFullPaths), map[string]bool{}, testTracker)

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
	c := config.CurrentConfig()
	snykCodeMock := &FakeSnykCodeClient{C: c}
	learnMock := mock_learn.NewMockService(gomock.NewController(t))
	learnMock.
		EXPECT().
		GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&learn.Lesson{}, nil).AnyTimes()
	scanner := New(NewBundler(c, snykCodeMock, NewCodeInstrumentor()), &snyk_api.FakeApiClient{CodeEnabled: true}, newTestCodeErrorReporter(), learnMock, notification.NewNotifier(), &FakeCodeScannerClient{})

	return snykCodeMock, scanner
}

func TestUploadAndAnalyze(t *testing.T) {
	c := testutil.UnitTest(t)
	channel := make(chan types.ProgressParams, 10000)
	cancelChannel := make(chan bool, 1)
	testTracker := progress.NewTestTracker(channel, cancelChannel)
	learnMock := mock_learn.NewMockService(gomock.NewController(t))
	learnMock.
		EXPECT().
		GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&learn.Lesson{}, nil).AnyTimes()
	t.Run(
		"should create bundle when hash empty", func(t *testing.T) {
			snykCodeMock := &FakeSnykCodeClient{C: c}
			s := New(NewBundler(c, snykCodeMock, NewCodeInstrumentor()), &snyk_api.FakeApiClient{CodeEnabled: true}, newTestCodeErrorReporter(), learnMock, notification.NewNotifier(), &FakeCodeScannerClient{})
			baseDir, firstDoc, _, content1, _ := setupDocs(t)
			fullPath := uri.PathFromUri(firstDoc.URI)
			docs := sliceToChannel([]string{fullPath})

			_, _ = s.UploadAndAnalyze(context.Background(), docs, baseDir, map[string]bool{}, testTracker)

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
			snykCodeMock := &FakeSnykCodeClient{C: c}
			scanner := New(NewBundler(c, snykCodeMock, NewCodeInstrumentor()), &snyk_api.FakeApiClient{CodeEnabled: true}, newTestCodeErrorReporter(), learnMock, notification.NewNotifier(), &FakeCodeScannerClient{})
			filePath, path := TempWorkdirWithIssues(t)
			defer func(path string) { _ = os.RemoveAll(path) }(path)
			files := []string{filePath}

			issues, _ := scanner.UploadAndAnalyze(context.Background(), sliceToChannel(files), path, map[string]bool{}, testTracker)

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
			scanner.bundleHashesMutex.RLock()
			defer scanner.bundleHashesMutex.RUnlock()
			assert.Equal(t, 1, len(scanner.bundleHashes))
			assert.Equal(t, snykCodeMock.Options[scanner.bundleHashes[path]].bundleHash, scanner.bundleHashes[path])
		},
	)
}

func TestUploadAndAnalyzeWithIgnores(t *testing.T) {
	c := testutil.UnitTest(t)
	learnMock := mock_learn.NewMockService(gomock.NewController(t))
	learnMock.
		EXPECT().
		GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&learn.Lesson{}, nil).AnyTimes()
	testutil.UnitTest(t)
	snykCodeMock := &FakeSnykCodeClient{C: c}
	filePath, workDir := TempWorkdirWithIssues(t)
	defer func(path string) { _ = os.RemoveAll(path) }(workDir)
	files := []string{filePath}
	fakeCodeScanner := &FakeCodeScannerClient{rootPath: workDir}
	channel := make(chan types.ProgressParams, 10000)
	cancelChannel := make(chan bool, 1)
	testTracker := progress.NewTestTracker(channel, cancelChannel)

	scanner := New(NewBundler(c, snykCodeMock, NewCodeInstrumentor()), &snyk_api.FakeApiClient{CodeEnabled: true}, newTestCodeErrorReporter(), learnMock, notification.NewNotifier(), fakeCodeScanner)
	issues, _ := scanner.UploadAndAnalyzeWithIgnores(context.Background(), workDir, sliceToChannel(files), map[string]bool{}, testTracker)

	assert.True(t, fakeCodeScanner.UploadAndAnalyzeWasCalled)
	assert.False(t, issues[0].IsIgnored)
	assert.Nil(t, issues[0].IgnoreDetails)
	assert.Equal(t, true, issues[1].IsIgnored)
	assert.Equal(t, "wont-fix", issues[1].IgnoreDetails.Category)
	assert.Equal(t, "False positive", issues[1].IgnoreDetails.Reason)
	assert.Equal(t, "2024-07-11T10:06:44Z", issues[1].IgnoreDetails.Expiration)
	assert.Equal(t, 2024, issues[1].IgnoreDetails.IgnoredOn.Year())
	assert.Equal(t, "Neil M", issues[1].IgnoreDetails.IgnoredBy)

	// verify that bundle hash has been saved
	scanner.bundleHashesMutex.RLock()
	defer scanner.bundleHashesMutex.RUnlock()
	assert.Equal(t, 1, len(scanner.bundleHashes))
	assert.Equal(t, snykCodeMock.Options[scanner.bundleHashes[workDir]].bundleHash, scanner.bundleHashes[workDir])
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
		c := testutil.UnitTest(t)
		snykCodeMock := &FakeSnykCodeClient{C: c}
		scanner := New(NewBundler(c, snykCodeMock, NewCodeInstrumentor()), &snyk_api.FakeApiClient{CodeEnabled: false}, newTestCodeErrorReporter(), nil, notification.NewNotifier(), &FakeCodeScannerClient{})
		tempDir, _, _ := setupIgnoreWorkspace(t)

		_, _ = scanner.Scan(context.Background(), "", tempDir)

		params := snykCodeMock.GetCallParams(0, CreateBundleOperation)
		assert.Nil(t, params)
	})

	//nolint:dupl // test cases differ by a boolean
	t.Run("Should run existing flow if feature flag is disabled", func(t *testing.T) {
		c := testutil.UnitTest(t)
		snykCodeMock := &FakeSnykCodeClient{C: c}
		snykApiMock := &snyk_api.FakeApiClient{CodeEnabled: true}
		snykApiMock.SetResponse("FeatureFlagStatus", snyk_api.FFResponse{Ok: false})
		learnMock := mock_learn.NewMockService(gomock.NewController(t))
		learnMock.
			EXPECT().
			GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&learn.Lesson{}, nil).AnyTimes()

		scanner := New(NewBundler(c, snykCodeMock, NewCodeInstrumentor()), snykApiMock, newTestCodeErrorReporter(), learnMock, notification.NewNotifier(), &FakeCodeScannerClient{})
		tempDir, _, _ := setupIgnoreWorkspace(t)

		_, _ = scanner.Scan(context.Background(), "", tempDir)

		params := snykCodeMock.GetCallParams(0, CreateBundleOperation)
		assert.NotNil(t, params)
	})

	//nolint:dupl // test cases differ by a boolean
	t.Run("Should run new flow if feature flag is enabled", func(t *testing.T) {
		c := testutil.UnitTest(t)
		snykCodeMock := &FakeSnykCodeClient{C: c}
		snykApiMock := &snyk_api.FakeApiClient{CodeEnabled: true}
		snykApiMock.SetResponse("FeatureFlagStatus", snyk_api.FFResponse{Ok: true})
		learnMock := mock_learn.NewMockService(gomock.NewController(t))
		learnMock.
			EXPECT().
			GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&learn.Lesson{}, nil).AnyTimes()

		scanner := New(NewBundler(c, snykCodeMock, NewCodeInstrumentor()), snykApiMock, newTestCodeErrorReporter(), learnMock, notification.NewNotifier(), &FakeCodeScannerClient{})
		tempDir, _, _ := setupIgnoreWorkspace(t)

		_, _ = scanner.Scan(context.Background(), "", tempDir)

		params := snykCodeMock.GetCallParams(0, CreateBundleOperation)
		assert.Nil(t, params)
	})
}

func Test_enhanceIssuesDetails(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Arrange
	learnMock := mock_learn.NewMockService(ctrl)
	errorReporterMock := newTestCodeErrorReporter()

	expectedLessonUrl := "https://learn.snyk.io/lesson/no-rate-limiting/?loc=ide"

	learnMock.
		EXPECT().
		GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&learn.Lesson{Url: expectedLessonUrl}, nil).AnyTimes()

	scanner := &Scanner{
		learnService:  learnMock,
		errorReporter: errorReporterMock,
		changedPaths:  make(map[string]map[string]bool),
		c:             c,
	}

	issues := []snyk.Issue{
		{
			CWEs:      []string{"CWE-123", "CWE-456"},
			ID:        "java/DontUsePrintStackTrace",
			Severity:  2,
			LessonUrl: expectedLessonUrl,
			AdditionalData: snyk.CodeIssueData{
				Title:          "Allocation of Resources Without Limits or Throttling",
				IsSecurityType: true,
				Message:        "Either rethrow this java.lang.InterruptedException or set the interrupted flag on the current thread with 'Thread.currentThread().interrupt()'. Otherwise the information that the current thread was interrupted will be lost.",
				PriorityScore:  890,
			},
		},
	}

	// Act
	scanner.enhanceIssuesDetails(issues, "")

	// Assert
	assert.Equal(t, expectedLessonUrl, issues[0].LessonUrl)
	assert.Contains(t, issues[0].AdditionalData.(snyk.CodeIssueData).Details, `href="https://learn.snyk.io/lesson/no-rate-limiting/?loc=ide"`)
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
	c := config.CurrentConfig()
	scanner := &Scanner{errorReporter: newTestCodeErrorReporter(), c: c}
	t.Run(
		"should return true if Snyk Code is generally enabled", func(t *testing.T) {
			config.CurrentConfig().SetSnykCodeEnabled(true)
			enabled := scanner.IsEnabled()
			assert.True(t, enabled)
		},
	)
	t.Run(
		"should return true if Snyk Code Quality is enabled", func(t *testing.T) {
			c.SetSnykCodeEnabled(false)
			c.EnableSnykCodeQuality(true)
			c.EnableSnykCodeSecurity(false)
			enabled := scanner.IsEnabled()
			assert.True(t, enabled)
		},
	)
	t.Run(
		"should return true if Snyk Code Security is enabled", func(t *testing.T) {
			c.SetSnykCodeEnabled(false)
			c.EnableSnykCodeQuality(false)
			c.EnableSnykCodeSecurity(true)
			enabled := scanner.IsEnabled()
			assert.True(t, enabled)
		},
	)
	t.Run(
		"should return false if Snyk Code is disabled and Snyk Code Quality and Security are not enabled",
		func(t *testing.T) {
			c.SetSnykCodeEnabled(false)
			c.EnableSnykCodeQuality(false)
			c.EnableSnykCodeSecurity(false)
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
	channel := make(chan types.ProgressParams, 10000)
	cancelChannel := make(chan bool, 1)
	testTracker := progress.NewTestTracker(channel, cancelChannel)

	t.Run(
		"should not add autofix after analysis when not enabled", func(t *testing.T) {
			c := testutil.UnitTest(t)
			autofixSetupAndCleanup(t)

			snykCodeMock := &FakeSnykCodeClient{C: c}
			scanner := New(NewBundler(c, snykCodeMock, NewCodeInstrumentor()), &snyk_api.FakeApiClient{CodeEnabled: true}, newTestCodeErrorReporter(), learnMock, notification.NewNotifier(), &FakeCodeScannerClient{})
			diagnosticUri, path := TempWorkdirWithIssues(t)
			t.Cleanup(
				func() {
					_ = os.RemoveAll(path)
				},
			)
			files := []string{diagnosticUri}

			// execute
			issues, _ := scanner.UploadAndAnalyze(context.Background(), sliceToChannel(files), "", map[string]bool{}, testTracker)

			// Default is to have 1 fake action from analysis + 0 from autofix
			assert.Len(t, issues[0].CodeActions, 1)
		},
	)

	t.Run(
		"should not provide autofix code action when autofix enabled but issue not fixable",
		func(t *testing.T) {
			c := testutil.UnitTest(t)
			autofixSetupAndCleanup(t)
			getCodeSettings().isAutofixEnabled.Set(true)

			snykCodeMock := &FakeSnykCodeClient{C: c}
			snykCodeMock.NoFixSuggestions = true

			scanner := New(NewBundler(c, snykCodeMock, NewCodeInstrumentor()), &snyk_api.FakeApiClient{CodeEnabled: true}, newTestCodeErrorReporter(), learnMock, notification.NewNotifier(), &FakeCodeScannerClient{})
			diagnosticUri, path := TempWorkdirWithIssues(t)
			t.Cleanup(
				func() {
					_ = os.RemoveAll(path)
				},
			)
			files := []string{diagnosticUri}

			// execute
			issues, _ := scanner.UploadAndAnalyze(context.Background(), sliceToChannel(files), "", map[string]bool{}, testTracker)

			// Default is to have 1 fake action from analysis + 0 from autofix
			assert.Len(t, issues[0].CodeActions, 1)
		},
	)

	t.Run(
		"should run autofix after analysis when is enabled", func(t *testing.T) {
			c := testutil.UnitTest(t)
			autofixSetupAndCleanup(t)
			getCodeSettings().isAutofixEnabled.Set(true)

			snykCodeMock := &FakeSnykCodeClient{C: c}
			scanner := New(NewBundler(c, snykCodeMock, NewCodeInstrumentor()), &snyk_api.FakeApiClient{CodeEnabled: true}, newTestCodeErrorReporter(), learnMock, notification.NewNotifier(), &FakeCodeScannerClient{})
			diagnosticUri, path := TempWorkdirWithIssues(t)
			t.Cleanup(
				func() {
					_ = os.RemoveAll(path)
				},
			)
			files := []string{diagnosticUri}

			// execute
			issues, _ := scanner.UploadAndAnalyze(context.Background(), sliceToChannel(files), "", map[string]bool{}, testTracker)

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
		changedFile1 := "file1.java"
		changedFile2 := "file2.java"
		scanner.changedPaths[tempDir][changedFile1] = true
		scanner.changedPaths[tempDir][changedFile2] = true

		files := scanner.getFilesToBeScanned(tempDir)

		require.Contains(t, files, changedFile1)
		require.Contains(t, files, changedFile2)
		require.Len(t, scanner.changedPaths[tempDir], 0)
	})

	t.Run("should add all files that have dataflow items of a changed file", func(t *testing.T) {
		changedFile := "main.ts"
		fromChangeAffectedFile := "juice-shop/routes/vulnCodeSnippet.ts"

		// add the changed file to the changed paths store
		scanner.changedPaths[tempDir][changedFile] = true

		// add the issue. The issue references `changedFile` in the dataflow
		issue := snyk.Issue{AdditionalData: getInterfileTestCodeIssueData()}
		scanner.issueCache.Set(fromChangeAffectedFile, []snyk.Issue{issue}, imcache.WithDefaultExpiration())
		defer scanner.issueCache.RemoveAll()

		files := scanner.getFilesToBeScanned(tempDir)

		// The `changedFile` is automatically scanned, but it is mentioned by `fromChangeAffectedFile` in the dataflow
		// Thus, now we should have both files
		require.Contains(t, files, changedFile)
		require.Contains(t, files, fromChangeAffectedFile)
	})
}

func TestNormalizeBranchName(t *testing.T) {
	branchName := " feat/new -$#@$#@$#@$@#"
	expectedBranchName := "featnew_-"

	normaliedBranchName := vcs.NormalizeBranchName(branchName)

	assert.Equal(t, expectedBranchName, normaliedBranchName)
}

func getInterfileTestCodeIssueData() snyk.CodeIssueData {
	return snyk.CodeIssueData{
		DataFlow: []snyk.DataFlowElement{
			{
				Content:  "if (!vulnLines.every(e => selectedLines.includes(e))) return false",
				FilePath: "juice-shop/routes/vulnCodeSnippet.ts",
				FlowRange: snyk.Range{
					End: snyk.Position{
						Character: 42,
						Line:      67,
					},
					Start: snyk.Position{
						Character: 28,
						Line:      67,
					},
				},
				Position: 0,
			},
			{
				Content:  "import { LoggerFactory } from './log';",
				FilePath: "main.ts",
				FlowRange: snyk.Range{
					End: snyk.Position{
						Character: 10,
						Line:      9,
					},
					Start: snyk.Position{
						Character: 9,
						Line:      97,
					},
				},
				Position: 4,
			},
		},
	}
}
