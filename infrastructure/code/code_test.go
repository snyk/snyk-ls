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
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/erni27/imcache"
	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	
	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/learn/mock_learn"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/vcs"

	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow"
	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow/sast_contract"
	"github.com/snyk/go-application-framework/pkg/mocks"
)

func setupTestData() (issue *snyk.Issue, expectedURI string, expectedTitle string) {
	issue = &snyk.Issue{
		AffectedFilePath: "/Users/user/workspace/blah/app.js",
		Product:          product.ProductCode,
		AdditionalData:   snyk.CodeIssueData{Key: "123", Title: "Test Issue"},
		Range:            fakeRange,
	}

	expectedURI = "snyk:///Users/user/workspace/blah/app.js?product=Snyk+Code&issueId=123&action=showInDetailPanel"
	expectedTitle = "⚡ Fix this issue: Test Issue (Snyk)"

	return
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

func setupTestScanner(t *testing.T) *Scanner {
	t.Helper()
	c := testutil.UnitTest(t)
	c.SetSnykCodeEnabled(true)
	mockEngine, engineConfig := testutil.SetUpEngineMock(t, c)

	engineConfig.Set(code_workflow.ConfigurationSastSettings, &sast_contract.SastResponse{SastEnabled: true})

	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()

	learnMock := mock_learn.NewMockService(gomock.NewController(t))
	learnMock.
		EXPECT().
		GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&learn.Lesson{}, nil).AnyTimes()
	scanner := New(c, performance.NewInstrumentor(), &snyk_api.FakeApiClient{CodeEnabled: true}, newTestCodeErrorReporter(), learnMock, notification.NewNotifier(), &FakeCodeScannerClient{})

	return scanner
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
		"should retrieve from backend", func(t *testing.T) {
			scanner := New(c, performance.NewInstrumentor(), &snyk_api.FakeApiClient{CodeEnabled: true}, newTestCodeErrorReporter(), learnMock, notification.NewNotifier(), &FakeCodeScannerClient{})
			filePath, path := TempWorkdirWithIssues(t)
			defer func(path string) { _ = os.RemoveAll(path) }(string(path))
			files := []string{string(filePath)}

			issues, _ := scanner.UploadAndAnalyze(t.Context(), path, sliceToChannel(files), map[types.FilePath]bool{}, false, testTracker)

			assert.NotNil(t, issues)
			assert.Equal(t, 2, len(issues))

			assert.Equal(t, "java/DontUsePrintStackTrace", issues[0].GetID())
			assert.Equal(t, "java/catchingInterruptedExceptionWithoutInterrupt", issues[1].GetID())

			// verify that bundle hash has been saved
			scanner.bundleHashesMutex.RLock()
			defer scanner.bundleHashesMutex.RUnlock()
			assert.Equal(t, 1, len(scanner.bundleHashes))
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
	filePath, workDir := TempWorkdirWithIssues(t)
	defer func(path string) { _ = os.RemoveAll(path) }(string(workDir))
	files := []string{string(filePath)}
	fakeCodeScanner := &FakeCodeScannerClient{rootPath: workDir}
	channel := make(chan types.ProgressParams, 10000)
	cancelChannel := make(chan bool, 1)
	testTracker := progress.NewTestTracker(channel, cancelChannel)

	scanner := New(c, performance.NewInstrumentor(), &snyk_api.FakeApiClient{CodeEnabled: true}, newTestCodeErrorReporter(), learnMock, notification.NewNotifier(), fakeCodeScanner)
	issues, _ := scanner.UploadAndAnalyze(t.Context(), workDir, sliceToChannel(files), map[types.FilePath]bool{}, true, testTracker)

	assert.True(t, fakeCodeScanner.UploadAndAnalyzeWasCalled)
	assert.False(t, issues[0].GetIsIgnored())
	assert.Nil(t, issues[0].GetIgnoreDetails())
	assert.Equal(t, true, issues[1].GetIsIgnored())
	assert.Equal(t, "wont-fix", issues[1].GetIgnoreDetails().Category)
	assert.Equal(t, "False positive", issues[1].GetIgnoreDetails().Reason)
	assert.Equal(t, "2024-07-11T10:06:44Z", issues[1].GetIgnoreDetails().Expiration)
	assert.Equal(t, 2024, issues[1].GetIgnoreDetails().IgnoredOn.Year())
	assert.Equal(t, "Neil M", issues[1].GetIgnoreDetails().IgnoredBy)

	// verify that bundle hash has been saved
	scanner.bundleHashesMutex.RLock()
	defer scanner.bundleHashesMutex.RUnlock()
	assert.Equal(t, 1, len(scanner.bundleHashes))
}

func Test_Scan(t *testing.T) {
	t.Run("Should reset changed files after successful scan", func(t *testing.T) {
		testutil.UnitTest(t)
		// Arrange
		scanner := setupTestScanner(t)
		wg := sync.WaitGroup{}
		tempDir := types.FilePath(t.TempDir())

		// Act
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func(i int) {
				_, _ = scanner.Scan(t.Context(), types.FilePath("file"+strconv.Itoa(i)+".go"), tempDir, nil)
				wg.Done()
			}(i)
		}
		wg.Wait()

		// Assert
		assert.Equal(t, 0, len(scanner.changedPaths[tempDir]))
	})

	t.Run("Shouldn't run if Sast is disabled", func(t *testing.T) {
		c := testutil.UnitTest(t)

		scanner := New(c, performance.NewInstrumentor(), &snyk_api.FakeApiClient{CodeEnabled: false}, newTestCodeErrorReporter(), nil, notification.NewNotifier(), &FakeCodeScannerClient{})
		tempDir, _, _ := setupIgnoreWorkspace(t)

		c.Engine().GetConfiguration().Set(code_workflow.ConfigurationSastSettings, &sast_contract.SastResponse{SastEnabled: false})
		_, _ = scanner.Scan(t.Context(), "", tempDir, nil)
	})

	testCases := []struct {
		name               string
		cciEnabled         bool
		createBundleCalled bool
	}{
		{
			name:               "Should run existing flow if feature flag is disabled",
			cciEnabled:         false,
			createBundleCalled: true,
		},
		{
			name:               "Should run new flow if feature flag is enabled",
			cciEnabled:         true,
			createBundleCalled: false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := testutil.UnitTest(t)
			snykApiMock := &snyk_api.FakeApiClient{CodeEnabled: true}
			ctrl := gomock.NewController(t)
			mockConfiguration := mocks.NewMockConfiguration(ctrl)
			c.Engine().SetConfiguration(mockConfiguration)
			mockConfiguration.EXPECT().GetWithError(code_workflow.ConfigurationSastSettings).Return(&sast_contract.SastResponse{SastEnabled: true}, nil)
			mockConfiguration.EXPECT().GetBool(configuration.FF_CODE_CONSISTENT_IGNORES).Return(tc.cciEnabled)
			learnMock := mock_learn.NewMockService(gomock.NewController(t))
			learnMock.
				EXPECT().
				GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
				Return(&learn.Lesson{}, nil).AnyTimes()

			scanner := New(c, performance.NewInstrumentor(), snykApiMock, newTestCodeErrorReporter(), learnMock, notification.NewNotifier(), &FakeCodeScannerClient{})
			tempDir, _, _ := setupIgnoreWorkspace(t)

			issues, err := scanner.Scan(t.Context(), "", tempDir, nil)
			assert.Nil(t, err)
			assert.NotNil(t, issues)
		})
	}
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
		changedPaths:  make(map[types.FilePath]map[types.FilePath]bool),
		C:             c,
	}

	issues := []types.Issue{
		&snyk.Issue{
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
	scanner.enhanceIssuesDetails(issues)
	// Create a fake API client with the feature flag disabled
	apiClient := &snyk_api.FakeApiClient{
		CodeEnabled: true,
	}
	// Set the response for the FeatureFlagStatus method
	apiClient.SetResponse("FeatureFlagStatus", snyk_api.FFResponse{Ok: false})

	// invoke method under test
	htmlRenderer, err := GetHTMLRenderer(c, apiClient)
	assert.Nil(t, err)
	html := htmlRenderer.GetDetailsHtml(issues[0])
	// Assert
	assert.Equal(t, expectedLessonUrl, issues[0].GetLessonUrl())
	assert.Contains(t, html, `href="https://learn.snyk.io/lesson/no-rate-limiting/?loc=ide"`)
}

func setupIgnoreWorkspace(t *testing.T) (tempDir types.FilePath, ignoredFilePath types.FilePath, notIgnoredFilePath types.FilePath) {
	t.Helper()
	expectedPatterns := "*.xml\n**/*.txt\nbin"
	tempDir = writeTestGitIgnore(t, expectedPatterns)

	ignoredFilePath = types.FilePath(filepath.Join(string(tempDir), "ignored.xml"))
	err := os.WriteFile(string(ignoredFilePath), []byte("test"), 0600)
	if err != nil {
		t.Fatal(t, err, "Couldn't write ignored file ignored.xml")
	}
	notIgnoredFilePath = types.FilePath(filepath.Join(string(tempDir), "not-ignored.java"))
	err = os.WriteFile(string(notIgnoredFilePath), []byte("test"), 0600)
	if err != nil {
		t.Fatal(t, err, "Couldn't write ignored file not-ignored.java")
	}
	ignoredDir := filepath.Join(string(tempDir), "bin")
	err = os.Mkdir(ignoredDir, 0755)
	if err != nil {
		t.Fatal(t, err, "Couldn't write ignoreDirectory %s", ignoredDir)
	}

	return tempDir, ignoredFilePath, notIgnoredFilePath
}

func writeTestGitIgnore(t *testing.T, ignorePatterns string) (tempDir types.FilePath) {
	t.Helper()
	tempDir = types.FilePath(t.TempDir())
	writeGitIgnoreIntoDir(t, ignorePatterns, tempDir)
	return tempDir
}

func writeGitIgnoreIntoDir(t *testing.T, ignorePatterns string, tempDir types.FilePath) {
	t.Helper()
	filePath := filepath.Join(string(tempDir), ".gitignore")
	err := os.WriteFile(filePath, []byte(ignorePatterns), 0600)
	if err != nil {
		t.Fatal(t, err, "Couldn't write .gitignore")
	}
}

func Test_IsEnabled(t *testing.T) {
	c := testutil.UnitTest(t)
	scanner := &Scanner{errorReporter: newTestCodeErrorReporter(), C: c}
	t.Run(
		"should return true if Snyk Code is generally enabled", func(t *testing.T) {
			config.CurrentConfig().SetSnykCodeEnabled(true)
			enabled := scanner.IsEnabled()
			assert.True(t, enabled)
		},
	)
	t.Run(
		"should return true if Snyk Code Security is enabled", func(t *testing.T) {
			c.SetSnykCodeEnabled(false)
			c.EnableSnykCodeSecurity(true)
			enabled := scanner.IsEnabled()
			assert.True(t, enabled)
		},
	)
	t.Run(
		"should return false if Snyk Code is disabled and Security is not enabled",
		func(t *testing.T) {
			c.SetSnykCodeEnabled(false)
			c.EnableSnykCodeSecurity(false)
			enabled := scanner.IsEnabled()
			assert.False(t, enabled)
		},
	)
}

func autofixSetupAndCleanup(t *testing.T, c *config.Config) {
	t.Helper()
	resetCodeSettings()
	t.Cleanup(resetCodeSettings)
	c.SetSnykCodeEnabled(true)
	getCodeSettings().isAutofixEnabled.Set(false)
}

func TestUploadAnalyzeWithAutofix(t *testing.T) {
	learnMock := mock_learn.NewMockService(gomock.NewController(t))
	learnMock.
		EXPECT().
		GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&learn.Lesson{}, nil).AnyTimes()

	t.Run("should not add autofix after analysis when not enabled", func(t *testing.T) {
		c := testutil.UnitTest(t)
		channel := make(chan types.ProgressParams, 10000)
		cancelChannel := make(chan bool, 1)
		testTracker := progress.NewTestTracker(channel, cancelChannel)

		autofixSetupAndCleanup(t, c)
		scanner := New(c, performance.NewInstrumentor(), &snyk_api.FakeApiClient{CodeEnabled: true}, newTestCodeErrorReporter(), learnMock, notification.NewNotifier(), &FakeCodeScannerClient{})
		filePath, path := TempWorkdirWithIssues(t)
		t.Cleanup(
			func() {
				_ = os.RemoveAll(string(path))
			},
		)
		files := []string{string(filePath)}

		// execute
		issues, _ := scanner.UploadAndAnalyze(t.Context(), "", sliceToChannel(files), map[types.FilePath]bool{}, false, testTracker)

		// Default is to have 0 actions from analysis + 0 from autofix
		assert.Len(t, issues[0].GetCodeActions(), 0)
	},
	)

	t.Run("should run autofix after analysis when is enabled", func(t *testing.T) {
		c := testutil.UnitTest(t)
		issueEnhancer := IssueEnhancer{
			instrumentor: performance.NewInstrumentor(),
			c:            c,
		}
		channel := make(chan types.ProgressParams, 10000)
		cancelChannel := make(chan bool, 1)
		testTracker := progress.NewTestTracker(channel, cancelChannel)
		autofixSetupAndCleanup(t, c)
		getCodeSettings().isAutofixEnabled.Set(true)

		scanner := New(c, performance.NewInstrumentor(), &snyk_api.FakeApiClient{CodeEnabled: true}, newTestCodeErrorReporter(), learnMock, notification.NewNotifier(), &FakeCodeScannerClient{})
		filePath, path := TempWorkdirWithIssues(t)
		files := []string{string(filePath)}

		// execute
		issues, _ := scanner.UploadAndAnalyze(t.Context(), path, sliceToChannel(files), map[types.FilePath]bool{}, false, testTracker)

		// Only one of the returned issues is Autofix eligible; see getSarifResponseJson2 in fake_code_client_scanner.go.
		assert.Len(t, issues[0].GetCodeActions(), 1)
		assert.Len(t, issues[1].GetCodeActions(), 0)

		expectedCodeAction := issueEnhancer.createShowDocumentCodeAction(issues[0])
		action := issues[0].GetCodeActions()[0]
		assert.Equal(t, action.GetTitle(), expectedCodeAction.GetTitle())
		assert.Equal(t, action.GetTitle(), expectedCodeAction.GetCommand().Title)
		assert.Equal(t, action.GetCommand().CommandId, expectedCodeAction.GetCommand().CommandId)
		assert.Equal(t, action.GetCommand().Arguments, expectedCodeAction.GetCommand().Arguments)
	},
	)
}

func TestIssueEnhancer_createShowDocumentCodeAction(t *testing.T) {
	c := testutil.UnitTest(t)
	issueEnhancer := IssueEnhancer{
		instrumentor: performance.NewInstrumentor(),
		c:            c,
	}

	t.Run("creates show document code action successfully", func(t *testing.T) {
		issue, expectedURI, expectedTitle := setupTestData()
		codeAction := issueEnhancer.createShowDocumentCodeAction(issue)

		assert.NotNil(t, codeAction)
		assert.Equal(t, expectedTitle, codeAction.GetTitle())
		assert.NotNil(t, codeAction.GetCommand())
		assert.Equal(t, expectedTitle, codeAction.GetCommand().Title)
		assert.Equal(t, types.NavigateToRangeCommand, codeAction.GetCommand().CommandId)
		assert.Equal(t, expectedURI, codeAction.GetCommand().Arguments[0])
		assert.Equal(t, issue.Range, codeAction.GetCommand().Arguments[1])
	})
}

func TestScanner_getFilesToBeScanned(t *testing.T) {
	config.CurrentConfig().SetSnykCodeEnabled(true)
	scanner := setupTestScanner(t)
	tempDir := types.FilePath(t.TempDir())
	scanner.changedPaths = make(map[types.FilePath]map[types.FilePath]bool)
	scanner.changedPaths[tempDir] = make(map[types.FilePath]bool)

	t.Run("should add all files from changedPaths map and delete them from changedPaths", func(t *testing.T) {
		changedFile1 := types.FilePath("file1.java")
		changedFile2 := types.FilePath("file2.java")
		scanner.changedPaths[tempDir][changedFile1] = true
		scanner.changedPaths[tempDir][changedFile2] = true

		files := scanner.getFilesToBeScanned(tempDir)

		require.Contains(t, files, changedFile1)
		require.Contains(t, files, changedFile2)
		require.Len(t, scanner.changedPaths[tempDir], 0)
	})

	t.Run("should add all files that have dataflow items of a changed file", func(t *testing.T) {
		changedFile := types.FilePath("main.ts")
		fromChangeAffectedFile := types.FilePath("juice-shop/routes/vulnCodeSnippet.ts")

		// add the changed file to the changed paths store
		scanner.changedPaths[tempDir][changedFile] = true

		// add the issue. The issue references `changedFile` in the dataflow
		issue := &snyk.Issue{AdditionalData: getInterfileTestCodeIssueData()}
		scanner.issueCache.Set(fromChangeAffectedFile, []types.Issue{issue}, imcache.WithDefaultExpiration())
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
				FlowRange: types.Range{
					End: types.Position{
						Character: 42,
						Line:      67,
					},
					Start: types.Position{
						Character: 28,
						Line:      67,
					},
				},
				Position: 0,
			},
			{
				Content:  "import { LoggerFactory } from './log';",
				FilePath: "main.ts",
				FlowRange: types.Range{
					End: types.Position{
						Character: 10,
						Line:      9,
					},
					Start: types.Position{
						Character: 9,
						Line:      97,
					},
				},
				Position: 4,
			},
		},
	}
}
