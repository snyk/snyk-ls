/*
 * © 2022-2026 Snyk Limited
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
	"sync"
	"testing"

	"github.com/erni27/imcache"
	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	codeClient "github.com/snyk/code-client-go"
	"github.com/snyk/code-client-go/pkg/code"
	"github.com/snyk/code-client-go/pkg/code/sast_contract"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/learn/mock_learn"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/infrastructure/utils"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/testutil/workspaceutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
	"github.com/snyk/snyk-ls/internal/vcs"
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

func setupTestScanner(t *testing.T) (*Scanner, workflow.Engine) {
	t.Helper()
	engine := testutil.UnitTest(t)

	mockEngine, realConfig := testutil.SetUpEngineMock(t, engine)
	_ = mockEngine
	engine.GetConfiguration().Set(configuration.UserGlobalKey(types.SettingSnykCodeEnabled), true)

	// Set up feature flag service with SAST settings
	fakeFeatureFlagService := featureflag.NewFakeService()
	fakeFeatureFlagService.SastSettings = &sast_contract.SastResponse{SastEnabled: true}
	fakeFeatureFlagService.Conf = realConfig

	scanner := New(engine,
		performance.NewInstrumentor(),
		&snyk_api.FakeApiClient{CodeEnabled: true},
		newTestCodeErrorReporter(),
		setupMockLearnServiceNoLessons(t),
		fakeFeatureFlagService,
		notification.NewNotifier(),
		NewCodeInstrumentor(),
		newTestCodeErrorReporter(),
		NewFakeCodeScannerClient,
		defaultResolver(engine))

	return scanner, engine
}

func getTestFolderConfig(engine workflow.Engine, folderPath types.FilePath) *types.FolderConfig {
	fc := &types.FolderConfig{
		FolderPath:     folderPath,
		ConfigResolver: testutil.DefaultConfigResolver(engine),
	}
	types.SetSastSettings(engine.GetConfiguration(), folderPath, &sast_contract.SastResponse{
		SastEnabled:    true,
		AutofixEnabled: true,
	})
	return fc
}

func defaultResolver(engine workflow.Engine) types.ConfigResolverInterface {
	return testutil.DefaultConfigResolver(engine)
}

func TestUploadAndAnalyze(t *testing.T) {
	engine := testutil.UnitTest(t)
	channel := make(chan types.ProgressParams, 10000)
	cancelChannel := make(chan bool, 1)
	testTracker := progress.NewTestTracker(channel, cancelChannel, engine.GetLogger())

	t.Run(
		"should retrieve from backend", func(t *testing.T) {
			scanner := New(engine,
				performance.NewInstrumentor(),
				&snyk_api.FakeApiClient{CodeEnabled: true},
				newTestCodeErrorReporter(),
				setupMockLearnServiceNoLessons(t),
				featureflag.NewFakeService(),
				notification.NewNotifier(),
				NewCodeInstrumentor(),
				newTestCodeErrorReporter(),
				NewFakeCodeScannerClient,
				defaultResolver(engine))
			filePath, path := TempWorkdirWithIssues(t)
			defer func(path string) { _ = os.RemoveAll(path) }(string(path))
			files := []string{string(filePath)}
			engineConfig := engine.GetConfiguration()
			types.SetPreferredOrgAndOrgSetByUser(engineConfig, path, "test-org", true)
			folderConfig := &types.FolderConfig{FolderPath: path}
			folderConfig.SetConf(engineConfig)

			issues, err := scanner.UploadAndAnalyze(t.Context(), path, folderConfig, sliceToChannel(files), map[types.FilePath]bool{}, false, testTracker)
			require.NoError(t, err)

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
	engine := testutil.UnitTest(t)
	filePath, workDir := TempWorkdirWithIssues(t)
	defer func(path string) { _ = os.RemoveAll(path) }(string(workDir))
	files := []string{string(filePath)}
	channel := make(chan types.ProgressParams, 10000)
	cancelChannel := make(chan bool, 1)
	testTracker := progress.NewTestTracker(channel, cancelChannel, engine.GetLogger())

	scanner := New(
		engine,
		performance.NewInstrumentor(),
		&snyk_api.FakeApiClient{CodeEnabled: true},
		newTestCodeErrorReporter(),
		setupMockLearnServiceNoLessons(t),
		featureflag.NewFakeService(),
		notification.NewNotifier(),
		NewCodeInstrumentor(),
		newTestCodeErrorReporter(),
		NewFakeCodeScannerClient,
		defaultResolver(engine),
	)

	engineConfig := engine.GetConfiguration()
	types.SetPreferredOrgAndOrgSetByUser(engineConfig, workDir, "test-org", true)
	folderConfig := &types.FolderConfig{FolderPath: workDir}
	folderConfig.SetConf(engineConfig)
	issues, err := scanner.UploadAndAnalyze(t.Context(), workDir, folderConfig, sliceToChannel(files), map[types.FilePath]bool{}, true, testTracker)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(issues), 2, "scan should return at least 2 issues")
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

// Test_Scan_UsesConfigResolverFromContext FC-066: Code scanner uses resolver from context when available
func Test_Scan_UsesConfigResolverFromContext(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	engine := testutil.UnitTest(t)
	mockResolver := mock_types.NewMockConfigResolverInterface(ctrl)
	mockResolver.EXPECT().
		IsProductEnabledForFolder(product.ProductCode, gomock.Any()).
		Return(false).
		Times(1)

	scanner := New(engine, performance.NewInstrumentor(), &snyk_api.FakeApiClient{CodeEnabled: false}, newTestCodeErrorReporter(), nil, featureflag.NewFakeService(), notification.NewNotifier(), NewCodeInstrumentor(), newTestCodeErrorReporter(), NewFakeCodeScannerClient, defaultResolver(engine))
	folderConfig := &types.FolderConfig{FolderPath: types.FilePath(t.TempDir())}
	ctx := ctx2.NewContextWithConfigResolver(context.Background(), mockResolver)
	ctx = ctx2.NewContextWithFolderConfig(ctx, folderConfig)

	issues, err := scanner.Scan(ctx, "")

	assert.NoError(t, err)
	assert.Empty(t, issues)
}

// Test_Scan_FallsBackToStructFieldWhenNoResolverInContext FC-064: Code scanner falls back to struct field when context has no resolver
func Test_Scan_FallsBackToStructFieldWhenNoResolverInContext(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	engine := testutil.UnitTest(t)
	mockResolver := mock_types.NewMockConfigResolverInterface(ctrl)
	mockResolver.EXPECT().
		IsProductEnabledForFolder(product.ProductCode, gomock.Any()).
		Return(false).
		Times(1)

	scanner := New(engine, performance.NewInstrumentor(), &snyk_api.FakeApiClient{CodeEnabled: false}, newTestCodeErrorReporter(), nil, featureflag.NewFakeService(), notification.NewNotifier(), NewCodeInstrumentor(), newTestCodeErrorReporter(), NewFakeCodeScannerClient, mockResolver)
	folderConfig := &types.FolderConfig{FolderPath: types.FilePath(t.TempDir())}
	ctx := ctx2.NewContextWithFolderConfig(context.Background(), folderConfig)

	issues, err := scanner.Scan(ctx, "")

	assert.NoError(t, err)
	assert.Empty(t, issues)
}

func Test_Scan(t *testing.T) {
	t.Run("Should reset changed files after successful scan", func(t *testing.T) {
		scanner, engine := setupTestScanner(t)
		// Arrange
		wg := sync.WaitGroup{}
		tempDir := types.FilePath(t.TempDir())

		// Act
		folderConfig := getTestFolderConfig(engine, tempDir)
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func(i int) {
				ctx := ctx2.NewContextWithFolderConfig(t.Context(), folderConfig)
				_, _ = scanner.Scan(ctx, types.FilePath("file"+strconv.Itoa(i)+".go"))
				wg.Done()
			}(i)
		}
		wg.Wait()

		// Assert
		assert.Equal(t, 0, len(scanner.changedPaths[tempDir]))
	})

	t.Run("Shouldn't run if Sast is disabled", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		_, realConfig := testutil.SetUpEngineMock(t, engine)

		resolver := testutil.DefaultConfigResolver(engine)

		scanner := New(engine, performance.NewInstrumentor(), &snyk_api.FakeApiClient{CodeEnabled: false}, newTestCodeErrorReporter(), nil, featureflag.NewFakeService(), notification.NewNotifier(), NewCodeInstrumentor(), newTestCodeErrorReporter(), NewFakeCodeScannerClient, defaultResolver(engine))
		tempDir, _, _ := setupIgnoreWorkspace(t)

		types.SetSastSettings(realConfig, tempDir, &sast_contract.SastResponse{SastEnabled: false})
		folderConfig := &types.FolderConfig{FolderPath: tempDir, ConfigResolver: resolver}
		ctx := ctx2.NewContextWithFolderConfig(t.Context(), folderConfig)
		_, _ = scanner.Scan(ctx, "")
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
			engine := testutil.UnitTest(t)
			snykApiMock := &snyk_api.FakeApiClient{CodeEnabled: true}
			ctrl := gomock.NewController(t)
			mockEngine := mocks.NewMockEngine(ctrl)
			realConfig := configuration.NewWithOpts(configuration.WithAutomaticEnv())
			realConfig.Set(code.ConfigurationSastSettings, &sast_contract.SastResponse{SastEnabled: true})
			mockEngine.EXPECT().GetConfiguration().Return(realConfig).AnyTimes()
			mockEngine.EXPECT().GetLogger().Return(engine.GetLogger()).AnyTimes()

			fakeFeatureFlagService := featureflag.NewFakeService()
			fakeFeatureFlagService.Flags[featureflag.SnykCodeConsistentIgnores] = tc.cciEnabled
			fakeFeatureFlagService.SastSettings = &sast_contract.SastResponse{SastEnabled: true}

			scanner := New(
				mockEngine,
				performance.NewInstrumentor(),
				snykApiMock,
				newTestCodeErrorReporter(),
				setupMockLearnServiceNoLessons(t),
				fakeFeatureFlagService,
				notification.NewNotifier(),
				NewCodeInstrumentor(),
				newTestCodeErrorReporter(),
				NewFakeCodeScannerClient,
				defaultResolver(mockEngine),
			)
			tempDir, _, _ := setupIgnoreWorkspace(t)

			ctx := ctx2.NewContextWithFolderConfig(t.Context(), getTestFolderConfig(mockEngine, tempDir))
			issues, err := scanner.Scan(ctx, "")
			assert.Nil(t, err)
			assert.NotNil(t, issues)
		})
	}
}

func Test_enhanceIssuesDetails(t *testing.T) {
	engine := testutil.UnitTest(t)
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

	scanner := New(engine, performance.NewInstrumentor(), &snyk_api.FakeApiClient{CodeEnabled: true}, errorReporterMock, learnMock, featureflag.NewFakeService(), notification.NewNotifier(), NewCodeInstrumentor(), newTestCodeErrorReporter(), NewFakeCodeScannerClient, defaultResolver(engine))

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
	htmlRenderer, err := GetHTMLRenderer(engine, featureflag.New(engine.GetConfiguration(), engine.GetLogger(), engine, testutil.DefaultConfigResolver(engine)))
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
	err := os.WriteFile(string(ignoredFilePath), []byte("test"), 0o600)
	if err != nil {
		t.Fatal(t, err, "Couldn't write ignored file ignored.xml")
	}
	notIgnoredFilePath = types.FilePath(filepath.Join(string(tempDir), "not-ignored.java"))
	err = os.WriteFile(string(notIgnoredFilePath), []byte("test"), 0o600)
	if err != nil {
		t.Fatal(t, err, "Couldn't write ignored file not-ignored.java")
	}
	ignoredDir := filepath.Join(string(tempDir), "bin")
	err = os.Mkdir(ignoredDir, 0o755)
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
	err := os.WriteFile(filePath, []byte(ignorePatterns), 0o600)
	if err != nil {
		t.Fatal(t, err, "Couldn't write .gitignore")
	}
}

func Test_IsEnabledForFolder(t *testing.T) {
	engine := testutil.UnitTest(t)
	scanner := New(engine, performance.NewInstrumentor(), &snyk_api.FakeApiClient{CodeEnabled: true}, newTestCodeErrorReporter(), nil, featureflag.NewFakeService(), notification.NewNotifier(), NewCodeInstrumentor(), newTestCodeErrorReporter(), NewFakeCodeScannerClient, defaultResolver(engine))
	folderConfig := &types.FolderConfig{FolderPath: types.FilePath(t.TempDir())}
	t.Run(
		"should return true if Snyk Code is generally enabled", func(t *testing.T) {
			engine.GetConfiguration().Set(configuration.UserGlobalKey(types.SettingSnykCodeEnabled), true)
			enabled := scanner.IsEnabledForFolder(folderConfig)
			assert.True(t, enabled)
		},
	)
	t.Run(
		"should return false if Snyk Code is disabled",
		func(t *testing.T) {
			engine.GetConfiguration().Set(configuration.UserGlobalKey(types.SettingSnykCodeEnabled), false)
			enabled := scanner.IsEnabledForFolder(folderConfig)
			assert.False(t, enabled)
		},
	)
}

func TestUploadAnalyzeWithAutofix(t *testing.T) {
	t.Run("should not add autofix after analysis when not enabled", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		engine.GetConfiguration().Set(configuration.UserGlobalKey(types.SettingSnykCodeEnabled), true)
		channel := make(chan types.ProgressParams, 10000)
		cancelChannel := make(chan bool, 1)
		testTracker := progress.NewTestTracker(channel, cancelChannel, engine.GetLogger())
		scanner := New(
			engine,
			performance.NewInstrumentor(),
			&snyk_api.FakeApiClient{CodeEnabled: true},
			newTestCodeErrorReporter(),
			setupMockLearnServiceNoLessons(t),
			featureflag.NewFakeService(),
			notification.NewNotifier(),
			NewCodeInstrumentor(),
			newTestCodeErrorReporter(), NewFakeCodeScannerClient,
			nil,
		)
		filePath, path := TempWorkdirWithIssues(t)
		t.Cleanup(
			func() {
				_ = os.RemoveAll(string(path))
			},
		)
		files := []string{string(filePath)}
		engineConfig := engine.GetConfiguration()
		types.SetPreferredOrgAndOrgSetByUser(engineConfig, path, "test-org", true)
		types.SetSastSettings(engineConfig, path, &sast_contract.SastResponse{
			SastEnabled:    true,
			AutofixEnabled: false,
		})
		folderConfig := &types.FolderConfig{
			FolderPath:     path,
			ConfigResolver: testutil.DefaultConfigResolver(engine),
		}

		// execute
		issues, err := scanner.UploadAndAnalyze(t.Context(), "", folderConfig, sliceToChannel(files), map[types.FilePath]bool{}, false, testTracker)
		require.NoError(t, err)
		require.NotEmpty(t, issues, "scan should return at least one issue")

		// Default is to have 0 actions from analysis + 0 from autofix
		assert.Len(t, issues[0].GetCodeActions(), 0)
	},
	)

	t.Run("should run autofix after analysis when is enabled", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		engineConfig := engine.GetConfiguration()
		resolver := types.NewConfigResolver(engine.GetLogger())
		resolver.SetPrefixKeyResolver(configresolver.New(engineConfig), engineConfig)

		types.SetSastSettings(engineConfig, "", &sast_contract.SastResponse{
			SastEnabled:    true,
			AutofixEnabled: true,
		})
		folderConfigWithAutofix := &types.FolderConfig{
			FolderPath:     "",
			ConfigResolver: resolver,
		}
		issueEnhancer := IssueEnhancer{
			instrumentor: performance.NewInstrumentor(),
			engine:       engine,
			folderConfig: folderConfigWithAutofix,
		}
		channel := make(chan types.ProgressParams, 10000)
		cancelChannel := make(chan bool, 1)
		testTracker := progress.NewTestTracker(channel, cancelChannel, engine.GetLogger())
		engine.GetConfiguration().Set(configuration.UserGlobalKey(types.SettingSnykCodeEnabled), true)

		scanner := New(
			engine,
			performance.NewInstrumentor(),
			&snyk_api.FakeApiClient{CodeEnabled: true},
			newTestCodeErrorReporter(),
			setupMockLearnServiceNoLessons(t),
			featureflag.NewFakeService(),
			notification.NewNotifier(),
			NewCodeInstrumentor(),
			newTestCodeErrorReporter(),
			NewFakeCodeScannerClient,
			defaultResolver(engine),
		)
		filePath, path := TempWorkdirWithIssues(t)
		files := []string{string(filePath)}
		types.SetPreferredOrgAndOrgSetByUser(engineConfig, path, "test-org", true)
		types.SetSastSettings(engineConfig, path, &sast_contract.SastResponse{
			SastEnabled:    true,
			AutofixEnabled: true,
		})
		folderConfig := &types.FolderConfig{
			FolderPath:     path,
			ConfigResolver: resolver,
		}

		// execute
		issues, err := scanner.UploadAndAnalyze(t.Context(), path, folderConfig, sliceToChannel(files), map[types.FilePath]bool{}, false, testTracker)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(issues), 2, "scan should return at least 2 issues")

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

func TestDeltaScanUsesFolderOrg(t *testing.T) {
	engine := testutil.UnitTest(t)

	channel := make(chan types.ProgressParams, 10000)
	cancelChannel := make(chan bool, 1)
	testTracker := progress.NewTestTracker(channel, cancelChannel, engine.GetLogger())

	// Set up the workspace folder and folder config with an org
	workspaceFolderPath := types.FilePath(t.TempDir())
	engineConfig := engine.GetConfiguration()
	types.SetPreferredOrgAndOrgSetByUser(engineConfig, workspaceFolderPath, "workspace-org-123", true)
	folderConfig := &types.FolderConfig{FolderPath: workspaceFolderPath}
	folderConfig.SetConf(engineConfig)

	// Create a separate temp directory with a dummy file for a delta scan to run on
	tempScanDir := t.TempDir()
	dummyFile := filepath.Join(tempScanDir, "test.java")
	err := os.WriteFile(dummyFile, []byte("class Test {}"), 0o644)
	require.NoError(t, err)

	// Track which folderConfig was passed to the code scanner
	var capturedFolderConfig *types.FolderConfig
	mockCodeScanner := func(sc *Scanner, fc *types.FolderConfig) (codeClient.CodeScanner, error) {
		capturedFolderConfig = fc
		return NewFakeCodeScannerClient(sc, fc)
	}

	scanner := New(
		engine,
		performance.NewInstrumentor(),
		&snyk_api.FakeApiClient{CodeEnabled: true},
		newTestCodeErrorReporter(),
		setupMockLearnServiceNoLessons(t),
		featureflag.NewFakeService(),
		notification.NewNotifier(),
		NewCodeInstrumentor(),
		newTestCodeErrorReporter(),
		mockCodeScanner,
		defaultResolver(engine),
	)

	// Simulate delta scan: scan path is the temp directory, but folderConfig has workspace folder
	files := []string{dummyFile}
	_, err = scanner.UploadAndAnalyze(
		t.Context(),
		types.FilePath(tempScanDir), // Scan path is temp dir (simulating delta scan)
		folderConfig,                // But folder config has workspace folder
		sliceToChannel(files),
		map[types.FilePath]bool{},
		false,
		testTracker,
	)
	require.NoError(t, err)

	// Verify: The code scanner should have received the workspace folderConfig, not the temp dir
	require.NotNil(t, capturedFolderConfig, "codeScanner should have been called with a folderConfig")
	assert.Equal(t, workspaceFolderPath, capturedFolderConfig.FolderPath,
		"Code scanner should use workspace folder from folderConfig, not the temp scan directory")
	assert.Equal(t, "workspace-org-123", capturedFolderConfig.PreferredOrg(),
		"Code scanner should use org from folderConfig")
}

func TestIssueEnhancer_createShowDocumentCodeAction(t *testing.T) {
	engine := testutil.UnitTest(t)
	issueEnhancer := IssueEnhancer{
		instrumentor: performance.NewInstrumentor(),
		engine:       engine,
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
	scanner, _ := setupTestScanner(t)
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
		scanner.Cache.Set(fromChangeAffectedFile, []types.Issue{issue}, imcache.WithDefaultExpiration())
		defer scanner.Cache.RemoveAll()

		files := scanner.getFilesToBeScanned(tempDir)

		// The `changedFile` is automatically scanned, but it is mentioned by `fromChangeAffectedFile` in the dataflow
		// Thus, now we should have both files
		require.Contains(t, files, changedFile)
		require.Contains(t, files, fromChangeAffectedFile)
	})
}

func TestNormalizeBranchName(t *testing.T) {
	testutil.UnitTest(t)
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

// setupMockConfigWithStorage sets up a real configuration (needed for folder config) and returns a fakeFeatureFlagService.
func setupMockConfigWithStorage(mockEngine *mocks.MockEngine, enableConsistentIgnores bool, sastEnabled bool, logger *zerolog.Logger) (configuration.Configuration, *featureflag.FakeFeatureFlagService) {
	realConfig := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	fs := pflag.NewFlagSet("test-mock-config", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	_ = realConfig.AddFlagSet(fs)

	mockEngine.EXPECT().GetConfiguration().Return(realConfig).AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(logger).AnyTimes()

	fakeFeatureFlagService := featureflag.NewFakeService()
	fakeFeatureFlagService.Flags[featureflag.SnykCodeConsistentIgnores] = enableConsistentIgnores
	fakeFeatureFlagService.SastSettings = &sast_contract.SastResponse{SastEnabled: sastEnabled}
	fakeFeatureFlagService.Conf = realConfig

	return realConfig, fakeFeatureFlagService
}

// setupFolderConfig creates a folder config and stores it in configuration.
func setupFolderConfig(t *testing.T, conf configuration.Configuration, logger *zerolog.Logger, folderPath types.FilePath, org string) *types.FolderConfig {
	t.Helper()
	types.SetPreferredOrgAndOrgSetByUser(conf, folderPath, org, true)
	folderConfig := &types.FolderConfig{FolderPath: folderPath}
	folderConfig.SetConf(conf)
	err := storedconfig.UpdateFolderConfig(conf, folderConfig, logger)
	require.NoError(t, err)
	return folderConfig
}

func Test_Scan_WithFolderSpecificOrganization(t *testing.T) {
	t.Run("Should use folder-specific organization for SAST settings check", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		ctrl := gomock.NewController(t)
		mockEngine := mocks.NewMockEngine(ctrl)

		tempDir := types.FilePath(t.TempDir())
		folderOrg := "folder-specific-org"

		realConfig, fakeFeatureFlagService := setupMockConfigWithStorage(mockEngine, false, true, engine.GetLogger())
		tokenService.SetToken(realConfig, "00000000-0000-0000-0000-000000000001")
		realConfig.Set(configuration.UserGlobalKey(types.SettingAuthenticationMethod), string(types.FakeAuthentication))
		realConfig.Set(configuration.UserGlobalKey(types.SettingSnykCodeEnabled), true)
		folderConfig := setupFolderConfig(t, realConfig, engine.GetLogger(), tempDir, folderOrg)
		fakeFeatureFlagService.PopulateFolderConfig(folderConfig)

		scanner := New(
			mockEngine,
			performance.NewInstrumentor(),
			&snyk_api.FakeApiClient{CodeEnabled: true},
			newTestCodeErrorReporter(),
			setupMockLearnServiceNoLessons(t),
			fakeFeatureFlagService,
			notification.NewNotifier(),
			NewCodeInstrumentor(),
			newTestCodeErrorReporter(),
			NewFakeCodeScannerClient,
			defaultResolver(mockEngine),
		)

		ctx := ctx2.NewContextWithFolderConfig(t.Context(), folderConfig)
		_, err := scanner.Scan(ctx, types.FilePath("test.go"))
		assert.NoError(t, err)
	})

	t.Run("Should fail when SAST is disabled for folder-specific organization", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		ctrl := gomock.NewController(t)
		mockEngine := mocks.NewMockEngine(ctrl)

		tempDir := types.FilePath(t.TempDir())
		folderOrg := "org-with-sast-disabled"

		realConfig, fakeFeatureFlagService := setupMockConfigWithStorage(mockEngine, false, false, engine.GetLogger())
		tokenService.SetToken(realConfig, "00000000-0000-0000-0000-000000000001")
		realConfig.Set(configuration.UserGlobalKey(types.SettingAuthenticationMethod), string(types.FakeAuthentication))
		realConfig.Set(configuration.UserGlobalKey(types.SettingSnykCodeEnabled), true)
		folderConfig := setupFolderConfig(t, realConfig, engine.GetLogger(), tempDir, folderOrg)
		fakeFeatureFlagService.PopulateFolderConfig(folderConfig)

		scanner := New(mockEngine, performance.NewInstrumentor(), &snyk_api.FakeApiClient{CodeEnabled: true}, newTestCodeErrorReporter(), nil, fakeFeatureFlagService, notification.NewNotifier(), NewCodeInstrumentor(), newTestCodeErrorReporter(), NewFakeCodeScannerClient, defaultResolver(mockEngine))

		ctx := ctx2.NewContextWithFolderConfig(t.Context(), folderConfig)
		issues, err := scanner.Scan(ctx, types.FilePath("test.go"))
		assert.Error(t, err)
		assert.ErrorContains(t, err, utils.ErrSnykCodeNotEnabled)
		assert.Empty(t, issues)
	})

	t.Run("Should use different SAST settings for different folder organizations", func(t *testing.T) {
		engine, tokenService := testutil.UnitTestWithEngine(t)
		ctrl := gomock.NewController(t)
		mockEngine := mocks.NewMockEngine(ctrl)

		tempDir1 := types.FilePath(t.TempDir())
		tempDir2 := types.FilePath(t.TempDir())
		org1 := "org-with-sast-enabled"
		org2 := "org-with-sast-disabled"

		realConfig, _ := setupMockConfigWithStorage(mockEngine, false, true, engine.GetLogger())
		tokenService.SetToken(realConfig, "00000000-0000-0000-0000-000000000001")
		realConfig.Set(configuration.UserGlobalKey(types.SettingAuthenticationMethod), string(types.FakeAuthentication))
		realConfig.Set(configuration.UserGlobalKey(types.SettingSnykCodeEnabled), true)
		fakeFeatureFlagService1 := featureflag.NewFakeService()
		fakeFeatureFlagService1.Flags[featureflag.SnykCodeConsistentIgnores] = false
		fakeFeatureFlagService1.SastSettings = &sast_contract.SastResponse{SastEnabled: true}
		fakeFeatureFlagService1.Conf = realConfig
		fakeFeatureFlagService2 := featureflag.NewFakeService()
		fakeFeatureFlagService2.Flags[featureflag.SnykCodeConsistentIgnores] = false
		fakeFeatureFlagService2.SastSettings = &sast_contract.SastResponse{SastEnabled: false}
		fakeFeatureFlagService2.Conf = realConfig

		folderConfig1 := setupFolderConfig(t, realConfig, engine.GetLogger(), tempDir1, org1)
		fakeFeatureFlagService1.PopulateFolderConfig(folderConfig1)
		folderConfig2 := setupFolderConfig(t, realConfig, engine.GetLogger(), tempDir2, org2)
		fakeFeatureFlagService2.PopulateFolderConfig(folderConfig2)

		learnMock := setupMockLearnServiceNoLessons(t)
		scanner1 := New(mockEngine, performance.NewInstrumentor(), &snyk_api.FakeApiClient{CodeEnabled: true}, newTestCodeErrorReporter(), learnMock, fakeFeatureFlagService1, notification.NewNotifier(), NewCodeInstrumentor(), newTestCodeErrorReporter(), NewFakeCodeScannerClient, defaultResolver(mockEngine))
		scanner2 := New(mockEngine, performance.NewInstrumentor(), &snyk_api.FakeApiClient{CodeEnabled: true}, newTestCodeErrorReporter(), learnMock, fakeFeatureFlagService2, notification.NewNotifier(), NewCodeInstrumentor(), newTestCodeErrorReporter(), NewFakeCodeScannerClient, defaultResolver(mockEngine))

		// Scan with org1 (should succeed since SAST is enabled)
		ctx1 := ctx2.NewContextWithFolderConfig(t.Context(), folderConfig1)
		issues1, err1 := scanner1.Scan(ctx1, types.FilePath("test1.go"))
		assert.NoError(t, err1)
		assert.NotNil(t, issues1)

		// Scan with org2 (should fail since SAST is disabled)
		ctx2Val := ctx2.NewContextWithFolderConfig(t.Context(), folderConfig2)
		issues2, err2 := scanner2.Scan(ctx2Val, types.FilePath("test2.go"))
		assert.Error(t, err2)
		assert.ErrorContains(t, err2, utils.ErrSnykCodeNotEnabled)
		assert.Empty(t, issues2)
	})
}

// setupMockLearnServiceNoLessons creates a mock learn service that returns an empty lesson for any GetLesson call.
// This is the default setup used by most tests that don't care about the learn service behavior.
func setupMockLearnServiceNoLessons(t *testing.T) *mock_learn.MockService {
	t.Helper()
	learnMock := mock_learn.NewMockService(gomock.NewController(t))
	learnMock.EXPECT().
		GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&learn.Lesson{}, nil).AnyTimes()
	return learnMock
}

func Test_resolveOrgToUUID(t *testing.T) {
	t.Run("returns UUID unchanged when input is already a UUID", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		testutil.SetUpEngineMock(t, engine)

		inputUUID := "550e8400-e29b-41d4-a716-446655440000"

		result, err := config.ResolveOrgToUUIDWithEngine(engine, inputUUID)

		assert.NoError(t, err)
		assert.Equal(t, inputUUID, result)
	})

	t.Run("returns error when slug cannot be resolved to UUID", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		testutil.SetUpEngineMock(t, engine)

		inputSlug := "invalid_slug"

		result, err := config.ResolveOrgToUUIDWithEngine(engine, inputSlug)

		// When configuration cannot resolve the slug to a UUID, it will return an empty string or the slug itself
		// Our function should detect this and return an error
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "could not be resolved to a valid UUID")
		assert.Empty(t, result)
	})

	t.Run("handles empty string", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		testutil.SetUpEngineMock(t, engine)

		inputEmpty := ""

		result, err := config.ResolveOrgToUUIDWithEngine(engine, inputEmpty)

		// Empty string is not a UUID, so it will try to resolve
		// When unauthenticated or unable to resolve, configuration returns empty string
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "could not be resolved to a valid UUID")
		assert.Empty(t, result)
	})
}

// testCodeConfigUsesFolderOrg is a shared helper function that tests CodeConfig creation
// uses the correct folder-specific org for a single folder scenario.
// This focuses on the core CodeConfig creation flow: FolderOrganization -> createCodeConfig -> CreateCodeScanner
func testCodeConfigUsesFolderOrg(
	t *testing.T,
	engine workflow.Engine,
	scanner *Scanner,
	folderPath types.FilePath,
	expectedOrg string,
) {
	t.Helper()

	// Verify FolderOrganization() returns the expected org
	folderOrg := config.FolderOrganization(engine.GetConfiguration(), folderPath, engine.GetLogger())
	assert.Equal(t, expectedOrg, folderOrg, "FolderOrganization should return folder's org")

	// Get FolderConfig for the folder
	folderConfig := config.GetFolderConfigFromEngine(engine, testutil.DefaultConfigResolver(engine), folderPath, engine.GetLogger())
	require.NotNil(t, folderConfig, "FolderConfig should not be nil")

	// Verify the CodeConfig has the correct org
	// This is what CreateCodeScanner uses internally, so we verify it first
	codeConfig, err := scanner.createCodeConfig(folderConfig)
	require.NoError(t, err, "createCodeConfig should succeed with folder's org")
	require.NotNil(t, codeConfig, "CodeConfig should not be nil")

	// Verify the org is correctly set in the config
	configOrg := codeConfig.Organization()
	assert.Equal(t, expectedOrg, configOrg, "CodeConfig should use folder's org")
}

func Test_CodeConfig_UsesFolderOrganization(t *testing.T) {
	engine := testutil.UnitTest(t)
	engine.GetConfiguration().Set(configuration.UserGlobalKey(types.SettingSnykCodeEnabled), true)

	// Set up two folders with different orgs
	folderPath1 := types.FilePath("/fake/test-folder-1")
	folderPath2 := types.FilePath("/fake/test-folder-2")
	folderOrg1 := "5b1ddf00-0000-0000-0000-000000000002"
	folderOrg2 := "5b1ddf00-0000-0000-0000-000000000003"

	// Set up workspace with the folders
	// This is required for FolderOrganizationForSubPath to work (used by GetCodeApiUrlForFolder)
	_, _ = workspaceutil.SetupWorkspace(t, engine, folderPath1, folderPath2)

	// Configure folder 1 with org1
	engineConfig := engine.GetConfiguration()
	types.SetPreferredOrgAndOrgSetByUser(engineConfig, folderPath1, folderOrg1, true)
	err := storedconfig.UpdateFolderConfig(engineConfig, &types.FolderConfig{FolderPath: folderPath1}, engine.GetLogger())
	require.NoError(t, err)

	// Configure folder 2 with org2
	types.SetPreferredOrgAndOrgSetByUser(engineConfig, folderPath2, folderOrg2, true)
	err = storedconfig.UpdateFolderConfig(engineConfig, &types.FolderConfig{FolderPath: folderPath2}, engine.GetLogger())
	require.NoError(t, err)

	// Create a scanner to test CreateCodeScanner (the actual function used in scanning)
	// This is called via sc.codeScanner() in UploadAndAnalyze during actual scans
	scanner := New(engine, performance.NewInstrumentor(), &snyk_api.FakeApiClient{CodeEnabled: true}, newTestCodeErrorReporter(), nil, featureflag.NewFakeService(), notification.NewNotifier(), NewCodeInstrumentor(), newTestCodeErrorReporter(), NewFakeCodeScannerClient, defaultResolver(engine))

	// Test folder 1
	t.Run("folder 1", func(t *testing.T) {
		testCodeConfigUsesFolderOrg(t, engine, scanner, folderPath1, folderOrg1)
	})

	// Test folder 2
	t.Run("folder 2", func(t *testing.T) {
		testCodeConfigUsesFolderOrg(t, engine, scanner, folderPath2, folderOrg2)
	})

	// Verify the orgs are different
	assert.NotEqual(t, folderOrg1, folderOrg2, "Folder orgs should be different")
}

func Test_CodeConfig_FallsBackToGlobalOrg(t *testing.T) {
	engine := testutil.UnitTest(t)
	engine.GetConfiguration().Set(configuration.UserGlobalKey(types.SettingSnykCodeEnabled), true)

	globalOrg := "00000000-0000-0000-0000-000000000004"
	config.SetOrganization(engine.GetConfiguration(), globalOrg)

	folderPath := types.FilePath("/fake/test-folder")

	// Set up workspace with the folder
	// This is required for FolderOrganizationForSubPath to work (used by GetCodeApiUrlForFolder)
	_, _ = workspaceutil.SetupWorkspace(t, engine, folderPath)

	// Verify FolderOrganization() returns the global org (fallback behavior)
	folderOrg := config.FolderOrganization(engine.GetConfiguration(), folderPath, engine.GetLogger())
	assert.Equal(t, globalOrg, folderOrg, "FolderOrganization should fall back to global org when no folder org is configured")

	// Get FolderConfig for the folder
	folderConfig := config.GetFolderConfigFromEngine(engine, testutil.DefaultConfigResolver(engine), folderPath, engine.GetLogger())
	require.NotNil(t, folderConfig, "FolderConfig should not be nil")

	// Create a scanner to test createCodeConfig
	scanner := New(engine, performance.NewInstrumentor(), &snyk_api.FakeApiClient{CodeEnabled: true}, newTestCodeErrorReporter(), nil, featureflag.NewFakeService(), notification.NewNotifier(), NewCodeInstrumentor(), newTestCodeErrorReporter(), NewFakeCodeScannerClient, defaultResolver(engine))

	// Verify the CodeConfig has the correct org
	codeConfig, err := scanner.createCodeConfig(folderConfig)
	require.NoError(t, err, "createCodeConfig should succeed with global org fallback")
	require.NotNil(t, codeConfig, "CodeConfig should not be nil")

	// Verify the org is correctly set in the config
	configOrg := codeConfig.Organization()
	assert.Equal(t, globalOrg, configOrg, "CodeConfig should fall back to global org when no folder org is set")
}

// Test_createCodeConfig_UsesOrgFromFolderConfigNotFromPath verifies that createCodeConfig uses the org from the
// passed FolderConfig parameter, not derived from the pathToScan path or global config.
// This is critical for delta scans where the scan path is a temp directory but the org
// should come from the original workspace's FolderConfig.
func Test_createCodeConfig_UsesOrgFromFolderConfigNotFromPath(t *testing.T) {
	engine := testutil.UnitTest(t)
	engine.GetConfiguration().Set(configuration.UserGlobalKey(types.SettingSnykCodeEnabled), true)

	// Setup three different orgs to ensure we're using the right one:
	// 1. Global default org - should NOT be used
	// 2. Org stored for the scan path - should NOT be used
	// 3. Org in the passed FolderConfig - SHOULD be used
	// Note: Code scanner requires valid UUID format orgs (validated by ResolveOrgToUUID)
	globalDefaultOrg := "11111111-1111-1111-1111-111111111111"
	orgStoredForPath := "22222222-2222-2222-2222-222222222222"
	expectedOrg := "33333333-3333-3333-3333-333333333333"

	// Set global default org
	config.SetOrganization(engine.GetConfiguration(), globalDefaultOrg)

	// Create a directory path that will be scanned
	scanPath := types.FilePath("/fake/scan-path")

	// Set up workspace with the scan path
	_, _ = workspaceutil.SetupWorkspace(t, engine, scanPath)

	// Store a different org for the scan path (simulating a workspace with its own org)
	engineConfig := engine.GetConfiguration()
	types.SetPreferredOrgAndOrgSetByUser(engineConfig, scanPath, orgStoredForPath, true)
	err := storedconfig.UpdateFolderConfig(engineConfig, &types.FolderConfig{FolderPath: scanPath}, engine.GetLogger())
	require.NoError(t, err)

	// Create the FolderConfig we'll pass to createCodeConfig - with a DIFFERENT org
	// This simulates delta scan where we pass a config with the original workspace's org.
	// Use a separate config so the passed config has expectedOrg, not orgStoredForPath.
	passedConf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	types.SetPreferredOrgAndOrgSetByUser(passedConf, scanPath, expectedOrg, true)
	passedFolderConfig := &types.FolderConfig{FolderPath: scanPath}
	passedFolderConfig.SetConf(passedConf)

	scanner := New(engine, performance.NewInstrumentor(), &snyk_api.FakeApiClient{CodeEnabled: true}, newTestCodeErrorReporter(), nil, featureflag.NewFakeService(), notification.NewNotifier(), NewCodeInstrumentor(), newTestCodeErrorReporter(), NewFakeCodeScannerClient, defaultResolver(engine))

	// Act - call createCodeConfig with the passed FolderConfig
	codeConfig, err := scanner.createCodeConfig(passedFolderConfig)
	require.NoError(t, err, "createCodeConfig should succeed")
	require.NotNil(t, codeConfig, "CodeConfig should not be nil")

	// Assert - verify the CodeConfig uses the org from the PASSED FolderConfig,
	// not from the path's stored config or global default
	configOrg := codeConfig.Organization()
	assert.Equal(t, expectedOrg, configOrg,
		"CodeConfig should use org from passed FolderConfig, not from path lookup or global config")
	assert.NotEqual(t, orgStoredForPath, configOrg,
		"CodeConfig should NOT use org stored for the scan path")
	assert.NotEqual(t, globalDefaultOrg, configOrg,
		"CodeConfig should NOT use global default org")
}

func Test_NewAutofixCodeRequestContext_UsesFolderOrganization(t *testing.T) {
	engine := testutil.UnitTest(t)
	engine.GetConfiguration().Set(configuration.UserGlobalKey(types.SettingSnykCodeEnabled), true)

	// Set up two folders with different orgs
	folderPath1 := types.FilePath("/fake/test-folder-1")
	folderPath2 := types.FilePath("/fake/test-folder-2")
	folderOrg1 := "5b1ddf00-0000-0000-0000-000000000002"
	folderOrg2 := "5b1ddf00-0000-0000-0000-000000000003"

	// Set up workspace with the folders
	// This is required for FolderOrganization to work (used by NewAutofixCodeRequestContext)
	_, _ = workspaceutil.SetupWorkspace(t, engine, folderPath1, folderPath2)

	// Configure folder 1 with org1
	engineConfig := engine.GetConfiguration()
	types.SetPreferredOrgAndOrgSetByUser(engineConfig, folderPath1, folderOrg1, true)
	err := storedconfig.UpdateFolderConfig(engineConfig, &types.FolderConfig{FolderPath: folderPath1}, engine.GetLogger())
	require.NoError(t, err)

	// Configure folder 2 with org2
	types.SetPreferredOrgAndOrgSetByUser(engineConfig, folderPath2, folderOrg2, true)
	err = storedconfig.UpdateFolderConfig(engineConfig, &types.FolderConfig{FolderPath: folderPath2}, engine.GetLogger())
	require.NoError(t, err)

	// Test folder 1
	t.Run("folder 1", func(t *testing.T) {
		requestContext := NewAutofixCodeRequestContext(engine, folderPath1)
		require.NotNil(t, requestContext, "RequestContext should not be nil")

		// Verify the request context uses the correct org
		// newCodeRequestContext calls FolderOrganization() which should return folderOrg1
		assert.Equal(t, folderOrg1, requestContext.Org.PublicId, "RequestContext should use folder 1's org")
		assert.NotEqual(t, folderOrg2, requestContext.Org.PublicId, "RequestContext should not use folder 2's org")
	})

	// Test folder 2
	t.Run("folder 2", func(t *testing.T) {
		requestContext := NewAutofixCodeRequestContext(engine, folderPath2)
		require.NotNil(t, requestContext, "RequestContext should not be nil")

		// Verify the request context uses the correct org
		assert.Equal(t, folderOrg2, requestContext.Org.PublicId, "RequestContext should use folder 2's org")
		assert.NotEqual(t, folderOrg1, requestContext.Org.PublicId, "RequestContext should not use folder 1's org")
	})

	// Verify the orgs are different
	assert.NotEqual(t, folderOrg1, folderOrg2, "Folder orgs should be different")
}
