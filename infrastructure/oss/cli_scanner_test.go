/*
 * © 2024-2025 Snyk Limited
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

package oss

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/subosito/gotenv"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/infrastructure/issuecache"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/learn/mock_learn"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/scans"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// folderConfigWithFlags creates a FolderConfig with the given feature flags set via configuration.
func folderConfigWithFlags(flags map[string]bool) *types.FolderConfig {
	prefixKeyConf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	fs := pflag.NewFlagSet("cli-scanner-test", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	_ = prefixKeyConf.AddFlagSet(fs)
	fm := workflow.ConfigurationOptionsFromFlagset(fs)
	logger := zerolog.Nop()
	resolver := types.NewConfigResolver(&logger)
	resolver.SetPrefixKeyResolver(configresolver.New(prefixKeyConf, fm), prefixKeyConf, fm)
	fc := &types.FolderConfig{
		FolderPath:     "/test",
		ConfigResolver: resolver,
	}
	for flag, val := range flags {
		fc.SetFeatureFlag(flag, val)
	}
	return fc
}

func TestCLIScanner_getAbsTargetFilePathForPackageManagers(t *testing.T) {
	testCases := []struct {
		name                       string
		displayTargetFile          string
		workDir                    string
		displayTargetFileInWorkDir string
		path                       string
		expected                   string
	}{
		{
			name:              "NPM root directory",
			displayTargetFile: "package-lock.json",
			workDir:           "/Users/cata/git/playground/juice-shop", // if we mock the workDir
			path:              "/Users/cata/git/playground/juice-shop",
			expected:          "/Users/cata/git/playground/juice-shop/package.json",
		},
		{
			name:                       "NPM sub directory",
			displayTargetFile:          "frontend/package.json",
			displayTargetFileInWorkDir: "package.json",
			workDir:                    "/Users/cata/git/playground/juice-shop", // if we mock the workDir
			path:                       "/Users/cata/git/playground/juice-shop",
			expected:                   "/Users/cata/git/playground/juice-shop/frontend/package.json",
		},
		{
			name:              "Poetry Sub Project (below the working directory)",
			displayTargetFile: "poetry-sample/pyproject.toml",
			workDir:           "/Users/cata/git/playground/python-goof",
			path:              "/Users/cata/git/playground/python-goof",
			expected:          "/Users/cata/git/playground/python-goof/poetry-sample/pyproject.toml",
		},
		{
			name:                       "Gradle multi-module",
			displayTargetFile:          "build.gradle",
			displayTargetFileInWorkDir: "build.gradle",
			workDir:                    "/Users/bdoetsch/workspace/gradle-multi-module",
			path:                       "/Users/bdoetsch/workspace/gradle-multi-module/sample-api",
			expected:                   "/Users/bdoetsch/workspace/gradle-multi-module/sample-api/build.gradle",
		},
		{
			name:              "Go Modules deeply nested",
			displayTargetFile: "build/resources/test/test-fixtures/oss/annotator/go.mod",
			workDir:           "/Users/cata/git/snyk/hammerhead/snyk-intellij-plugin",
			path:              "/Users/cata/git/snyk/hammerhead/snyk-intellij-plugin",
			expected:          "/Users/cata/git/snyk/hammerhead/snyk-intellij-plugin/build/resources/test/test-fixtures/oss/annotator/go.mod",
		},
		{
			name:              "Maven test fixtures",
			displayTargetFile: "src/test/resources/test-fixtures/oss/annotator/pom.xml",
			workDir:           "/Users/cata/git/snyk/hammerhead/snyk-intellij-plugin",
			path:              "/Users/cata/git/snyk/hammerhead/snyk-intellij-plugin",
			expected:          "/Users/cata/git/snyk/hammerhead/snyk-intellij-plugin/src/test/resources/test-fixtures/oss/annotator/pom.xml",
		},
		{
			name:              "Gemfile deep below working dir",
			displayTargetFile: ".bin/pact/lib/vendor/Gemfile.lock",
			workDir:           "/Users/bdoetsch/workspace/snyk-ls",
			path:              "/Users/bdoetsch/workspace/snyk-ls/.bin/pact/lib/vendor",
			expected:          "/Users/bdoetsch/workspace/snyk-ls/.bin/pact/lib/vendor/Gemfile",
		},
		{
			name:              "(win) NPM root directory",
			displayTargetFile: "package-lock.json",
			workDir:           "C:\\a\\cata\\git\\playground\\juice-shop",
			path:              "C:\\a\\cata\\git\\playground\\juice-shop",
			expected:          "C:\\a\\cata\\git\\playground\\juice-shop\\package.json",
		},
		{
			name:              "(win) Poetry Sub Project (below the working directory)",
			displayTargetFile: "poetry-sample\\pyproject.toml",
			workDir:           "C:\\a\\cata\\git\\playground\\python-goof",
			path:              "C:\\a\\cata\\git\\playground\\python-goof",
			expected:          "C:\\a\\cata\\git\\playground\\python-goof\\poetry-sample\\pyproject.toml",
		},
		{
			name:              "(win) Gradle multi-module",
			displayTargetFile: "build.gradle",
			workDir:           "C:\\a\\bdoetsch\\workspace\\gradle-multi-module",
			path:              "C:\\a\\bdoetsch\\workspace\\gradle-multi-module\\sample-api",
			expected:          "C:\\a\\bdoetsch\\workspace\\gradle-multi-module\\sample-api\\build.gradle",
		},
		{
			name:              "(win) Go Modules deeply nested",
			displayTargetFile: "build\\resources\\test\\test-fixtures\\oss\\annotator\\go.mod",
			workDir:           "C:\\a\\cata\\git\\snyk\\hammerhead\\snyk-intellij-plugin",
			path:              "C:\\a\\cata\\git\\snyk\\hammerhead\\snyk-intellij-plugin",
			expected:          "C:\\a\\cata\\git\\snyk\\hammerhead\\snyk-intellij-plugin\\build\\resources\\test\\test-fixtures\\oss\\annotator\\go.mod",
		},
		{
			name:              "(win) Maven test fixtures",
			displayTargetFile: "src\\test\\resources\\test-fixtures\\oss\\annotator\\pom.xml",
			workDir:           "C:\\a\\cata\\git\\snyk\\hammerhead\\snyk-intellij-plugin",
			path:              "C:\\a\\cata\\git\\snyk\\hammerhead\\snyk-intellij-plugin",
			expected:          "C:\\a\\cata\\git\\snyk\\hammerhead\\snyk-intellij-plugin\\src\\test\\resources\\test-fixtures\\oss\\annotator\\pom.xml",
		},
		{
			name:              "(win) Gemfile deep below working dir",
			displayTargetFile: ".bin\\pact\\lib\\vendor\\Gemfile.lock",
			workDir:           "C:\\Users\\bdoetsch\\workspace\\snyk-ls",
			path:              "C:\\Users\\bdoetsch\\workspace\\snyk-ls\\.bin\\pact\\lib\\vendor",
			expected:          "C:\\Users\\bdoetsch\\workspace\\snyk-ls\\.bin\\pact\\lib\\vendor\\Gemfile",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			engine := testutil.UnitTest(t)
			skipReason := "filepath is os dependent"
			prefix := "C:"
			if strings.HasPrefix(tc.workDir, prefix) {
				testsupport.OnlyOnWindows(t, skipReason)
			} else {
				testsupport.NotOnWindows(t, skipReason)
			}

			base := t.TempDir()
			adjustedExpected, _ := strings.CutPrefix(tc.expected, prefix)
			adjustedWorkDir, _ := strings.CutPrefix(tc.workDir, prefix)
			adjustedPath, _ := strings.CutPrefix(tc.path, prefix)
			expected := types.FilePath(filepath.Join(base, adjustedExpected))
			dir := filepath.Dir(string(expected))
			require.NoError(t, os.MkdirAll(dir, 0770))
			require.NoError(t, os.WriteFile(string(expected), []byte(expected), 0666))
			if tc.displayTargetFileInWorkDir != "" {
				absFile := filepath.Join(base, adjustedWorkDir, tc.displayTargetFileInWorkDir)
				require.NoError(t, os.WriteFile(absFile, []byte(tc.displayTargetFileInWorkDir), 0666))
			}

			actual := getAbsTargetFilePath(
				engine.GetLogger(),
				filepath.Join(base, adjustedPath),
				tc.displayTargetFile,
				types.FilePath(filepath.Join(base, adjustedWorkDir)),
				types.FilePath(filepath.Join(base, adjustedPath)),
			)
			assert.Equal(t, expected, actual)
		})
	}
}

func TestCLIScanner_getAbsTargetFilePathFallsBackToScannedManifest(t *testing.T) {
	engine := testutil.UnitTest(t)
	workDir := types.FilePath(filepath.Join(t.TempDir(), "workspace"))
	path := types.FilePath(filepath.Join(string(workDir), "package.json"))

	actual := getAbsTargetFilePath(engine.GetLogger(), "", "package.json", workDir, path)

	assert.Equal(t, path, actual)
}

func TestCLIScanner_prepareScanCommand_RemovesAllProjectsParam(t *testing.T) {
	engine := testutil.UnitTest(t)

	// Setup test CLI executor
	cliExecutor := cli.NewTestExecutorWithResponse(engine, "{}")

	// Setup the scanner with necessary dependencies
	instrumentor := performance.NewInstrumentor()
	errorReporter := error_reporting.NewTestErrorReporter(engine)
	learnMock := mock_learn.NewMockService(gomock.NewController(t))
	notifier := notification.NewMockNotifier()

	cliScanner := &CLIScanner{
		IssueCache:       issuecache.NewIssueCacheForProduct(engine, product.ProductOpenSource),
		engine:           engine,
		cli:              cliExecutor,
		instrumentor:     instrumentor,
		errorReporter:    errorReporter,
		learnService:     learnMock,
		notifier:         notifier,
		configResolver:   defaultResolver(t, engine),
		mutex:            &sync.RWMutex{},
		inlineValueMutex: &sync.RWMutex{},
		packageScanMutex: &sync.Mutex{},
		runningScans:     make(map[types.FilePath]*scans.ScanProgress),
		supportedFiles:   make(map[string]bool),
	}

	// Test case 1: Command contains --all-projects, should remove it initially
	t.Run("removes --all-projects from command", func(t *testing.T) {
		// Setup command with --all-projects
		initialArgs := []string{"--all-projects"}
		parameterBlacklist := map[string]bool{}
		path := types.FilePath("/path/to/project")
		folderConfig := &types.FolderConfig{FolderPath: path}

		// Call the method under test
		result, _ := cliScanner.prepareScanCommand(initialArgs, parameterBlacklist, path, folderConfig)

		// Verify that --all-projects was initially removed (it may be added back later in the method)
		// Count occurrences of --all-projects in the command
		allProjectsCount := 0
		for _, arg := range result {
			if arg == "--all-projects" {
				allProjectsCount++
			}
		}

		// Should be added exactly once at the end (after being removed initially)
		assert.Equal(t, 1, allProjectsCount, "--all-projects should be present exactly once in the final command")

		// The last item should be --all-projects (since it's added at the end if allowed)
		assert.Equal(t, "--all-projects", result[len(result)-1], "--all-projects should be the last parameter")
	})

	// Test case 2: Command with both --all-projects and a conflicting parameter
	t.Run("handles conflicting parameters with --all-projects", func(t *testing.T) {
		path := types.FilePath("/path/to/project")
		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingCliAdditionalOssParameters), []string{"--file=package.json"})
		defer engine.GetConfiguration().Unset(configresolver.UserGlobalKey(types.SettingCliAdditionalOssParameters))

		initialArgs := []string{"--all-projects"}
		parameterBlacklist := map[string]bool{}
		// Use nil folderConfig so config resolution uses global (UserGlobalKey)
		result, _ := cliScanner.prepareScanCommand(initialArgs, parameterBlacklist, path, nil)

		containsAllProjects := false
		for _, arg := range result {
			if arg == "--all-projects" {
				containsAllProjects = true
				break
			}
		}
		assert.False(t, containsAllProjects, "--all-projects should not be present when there are conflicting parameters")
		assert.Contains(t, result, "--file=package.json", "The conflicting parameter should be present")
	})

	// Test case 3: Any parameter on allProjectsParamBlacklist should prevent auto-appending --all-projects.
	t.Run("does not append --all-projects when a blacklisted parameter is present", func(t *testing.T) {
		testCases := []struct {
			name            string
			parameter       string
			expectedInCmd   string
			expectedMessage string
		}{
			{
				name:            "--file",
				parameter:       "--file=package.json",
				expectedInCmd:   "--file=package.json",
				expectedMessage: "--all-projects should not be present when --file is present",
			},
			{
				name:            "--package-manager",
				parameter:       "--package-manager=npm",
				expectedInCmd:   "--package-manager=npm",
				expectedMessage: "--all-projects should not be present when --package-manager is present",
			},
			{
				name:            "--project-name",
				parameter:       "--project-name=my-project",
				expectedInCmd:   "--project-name=my-project",
				expectedMessage: "--all-projects should not be present when --project-name is present",
			},
			{
				name:            "--yarn-workspaces",
				parameter:       "--yarn-workspaces",
				expectedInCmd:   "--yarn-workspaces",
				expectedMessage: "--all-projects should not be present when --yarn-workspaces is present",
			},
			{
				name:            "--docker",
				parameter:       "--docker",
				expectedInCmd:   "--docker",
				expectedMessage: "--all-projects should not be present when --docker is present",
			},
			{
				name:            "--all-sub-projects",
				parameter:       "--all-sub-projects",
				expectedInCmd:   "--all-sub-projects",
				expectedMessage: "--all-projects should not be present when --all-sub-projects is present",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingCliAdditionalOssParameters), []string{tc.parameter})
				defer engine.GetConfiguration().Unset(configresolver.UserGlobalKey(types.SettingCliAdditionalOssParameters))

				initialArgs := []string{}
				parameterBlacklist := map[string]bool{}
				path := types.FilePath("/path/to/project")
				// Use nil folderConfig so config resolution uses global (UserGlobalKey)
				result, _ := cliScanner.prepareScanCommand(initialArgs, parameterBlacklist, path, nil)

				assert.NotContains(t, result, "--all-projects", tc.expectedMessage)
				assert.Contains(t, result, tc.expectedInCmd, "Blacklisted parameter should be present")
			})
		}
	})
}

func TestConvertScanResultToIssues_IgnoredIssuesNotPropagated(t *testing.T) {
	engine := testutil.UnitTest(t)

	// Create a mock scan result with both ignored and non-ignored issues
	scanResult := &scanResult{
		ProjectName: "test-project",
		Vulnerabilities: []ossIssue{
			{
				Id:          "SNYK-1",
				Name:        "Regular Issue",
				Title:       "Regular Vulnerability",
				PackageName: "package1",
				Version:     "1.0.0",
				IsIgnored:   false,
			},
			{
				Id:          "SNYK-2",
				Name:        "Ignored Issue",
				Title:       "Ignored Vulnerability",
				PackageName: "package2",
				Version:     "2.0.0",
				IsIgnored:   true,
				Ignores: []ProjectIgnore{
					{
						Reason: "Test reason for ignoring",
					},
				},
			},
		},
	}

	// Mock dependencies
	workDir := types.FilePath("/test/workdir")
	targetFilePath := types.FilePath("/test/workdir/package.json")
	fileContent := []byte("test file content")

	// Create mock learn service and error reporter
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	learnService := mock_learn.NewMockService(ctrl)
	errorReporter := error_reporting.NewTestErrorReporter(engine)

	// Expect GetLesson to be called for the non-ignored issue (SNYK-1) when there's no AST node
	learnService.EXPECT().
		GetLesson("", "SNYK-1", nil, nil, types.DependencyVulnerability).
		Return(&learn.Lesson{Url: "https://learn.snyk.io/lesson/test"}, nil).
		AnyTimes()

	configResolver := testutil.DefaultConfigResolver(engine)
	issues := convertScanResultToIssues(engine, configResolver, scanResult, workDir, targetFilePath, fileContent, learnService, errorReporter, engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingFormat)), nil)

	assert.Equal(t, 1, len(issues), "Expected only one non-ignored issue")

	issue, ok := issues[0].(*snyk.Issue)
	require.True(t, ok, "Expected issue to be of type *snyk.Issue")
	assert.Equal(t, "SNYK-1", issue.ID, "Expected the non-ignored issue ID")
}

func Test_isForceLegacyCLI(t *testing.T) {
	t.Run("returns true when env var is set", func(t *testing.T) {
		t.Setenv("SNYK_FORCE_LEGACY_CLI", "1")
		assert.True(t, isForceLegacyCLI())
	})
	t.Run("returns false when env var is not set", func(t *testing.T) {
		assert.False(t, isForceLegacyCLI())
	})
}

func Test_findLegacyOnlyFlag(t *testing.T) {
	tests := []struct {
		name     string
		cmd      []string
		expected string
	}{
		{"--unmanaged flag", []string{"snyk", "test", "--json", "--unmanaged", "/tmp"}, "--unmanaged"},
		{"--print-graph flag", []string{"snyk", "test", "--print-graph"}, "--print-graph"},
		{"--print-deps flag", []string{"snyk", "test", "--print-deps"}, "--print-deps"},
		{"--print-dep-paths flag", []string{"snyk", "test", "--print-dep-paths"}, "--print-dep-paths"},
		{"no legacy flags", []string{"snyk", "test", "--json", "/tmp"}, ""},
		{"empty cmd", []string{}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, findLegacyOnlyFlag(tc.cmd))
		})
	}
}

func Test_findNewFeature(t *testing.T) {
	t.Run("returns FF name when risk score FF is set", func(t *testing.T) {
		fc := folderConfigWithFlags(map[string]bool{featureflag.UseExperimentalRiskScoreInCLI: true})
		assert.Equal(t, featureflag.UseExperimentalRiskScoreInCLI, findNewFeature(fc, []string{"snyk", "test"}))
	})
	t.Run("returns FF name when ostest FF is set", func(t *testing.T) {
		fc := folderConfigWithFlags(map[string]bool{featureflag.UseOsTest: true})
		assert.Equal(t, featureflag.UseOsTest, findNewFeature(fc, []string{"snyk", "test"}))
	})
	t.Run("returns flag when --reachability in cmd", func(t *testing.T) {
		fc := folderConfigWithFlags(map[string]bool{})
		assert.Equal(t, "--reachability", findNewFeature(fc, []string{"snyk", "test", "--reachability"}))
	})
	t.Run("returns flag when --sbom in cmd", func(t *testing.T) {
		fc := folderConfigWithFlags(map[string]bool{})
		assert.Equal(t, "--sbom", findNewFeature(fc, []string{"snyk", "test", "--sbom"}))
	})
	t.Run("returns empty when no new features", func(t *testing.T) {
		fc := folderConfigWithFlags(map[string]bool{})
		assert.Empty(t, findNewFeature(fc, []string{"snyk", "test"}))
	})
}

func TestCLIScanner_handleError_ExitOneDoesNotRetainCliOutput(t *testing.T) {
	engine := testutil.UnitTest(t)
	cliScanner := newHandleErrorTestScanner(t, engine)
	payload := []byte("[" + strings.Repeat("x", 4*1024*1024) + "]")
	err := commandExitError(t, 1)

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	cliFailed, handledErr := cliScanner.handleError("/tmp/package.json", err, payload, []string{"snyk", "test", "--json"})

	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	require.False(t, cliFailed)
	require.NoError(t, handledErr)
	assert.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(1024*1024), "exit=1 must not copy or log the full CLI stdout")
}

func TestCLIScanner_handleError_TruncatesOutputForCliFailures(t *testing.T) {
	engine := testutil.UnitTest(t)
	cliScanner := newHandleErrorTestScanner(t, engine)
	payload := []byte(strings.Repeat("x", 8*1024))
	err := commandExitError(t, 2)

	cliFailed, handledErr := cliScanner.handleError("/tmp/package.json", err, payload, []string{"snyk", "test", "--json"})

	require.True(t, cliFailed)
	var cliErr *types.CliError
	require.ErrorAs(t, handledErr, &cliErr)
	assert.LessOrEqual(t, len(cliErr.ErrorMessage), 4096+len(" ...[truncated]"))
	assert.True(t, strings.HasSuffix(cliErr.ErrorMessage, " ...[truncated]"))
}

func TestCLIScanner_legacyScan_StreamsCliStdout(t *testing.T) {
	engine := testutil.UnitTest(t)
	executor := &streamingExecutorForLegacyScanTest{
		stdout: io.NopCloser(strings.NewReader(threeElementArrayJSON)),
	}
	cliScanner := newHandleErrorTestScanner(t, engine)
	cliScanner.cli = executor
	cliScanner.learnService = getLearnMock(t)
	cliScanner.inlineValues = make(inlineValueMap)

	output, err := cliScanner.legacyScan(
		t.Context(),
		"/tmp/package.json",
		[]string{"snyk", "test", "--json"},
		&types.FolderConfig{FolderPath: "/tmp"},
		nil,
	)
	require.NoError(t, err)
	require.True(t, executor.streamUsed, "legacy OSS scan must use streaming execution when available")

	logger := zerolog.Nop()
	ctx := ctx2.NewContextWithLogger(t.Context(), &logger)
	ctx = ctx2.NewContextWithEngine(ctx, engine)
	ctx = ctx2.NewContextWithConfigResolver(ctx, defaultResolver(t, engine))
	ctx = ctx2.NewContextWithWorkDirAndFilePath(ctx, "/tmp", "/tmp/package.json")
	ctx = ctx2.NewContextWithFolderConfig(ctx, &types.FolderConfig{FolderPath: "/tmp"})

	issues, err := cliScanner.unmarshallAndRetrieveAnalysis(ctx, output, "/tmp", "/tmp/package.json", config.FormatMd)

	require.NoError(t, err)
	require.NotEmpty(t, issues)
	require.True(t, executor.waitCalled, "streaming CLI process must be waited after stdout is decoded")
}

func TestCLIScanner_legacyScan_PropagatesStreamingWaitExitCode2(t *testing.T) {
	engine := testutil.UnitTest(t)
	executor := &streamingExecutorForLegacyScanTest{
		stdout:  io.NopCloser(strings.NewReader("")),
		waitErr: commandExitError(t, 2),
	}
	cliScanner := newHandleErrorTestScanner(t, engine)
	cliScanner.cli = executor
	cliScanner.learnService = getLearnMock(t)
	cliScanner.inlineValues = make(inlineValueMap)

	logger := zerolog.Nop()
	ctx := ctx2.NewContextWithLogger(t.Context(), &logger)
	ctx = ctx2.NewContextWithEngine(ctx, engine)
	ctx = ctx2.NewContextWithConfigResolver(ctx, defaultResolver(t, engine))
	ctx = ctx2.NewContextWithWorkDirAndFilePath(ctx, "/tmp", "/tmp/package.json")
	ctx = ctx2.NewContextWithFolderConfig(ctx, &types.FolderConfig{FolderPath: "/tmp"})
	ctx = cliScanner.enrichContext(ctx)

	_, err := cliScanner.scanInternal(ctx, func(_ []string, _ map[string]bool, _ types.FilePath, _ *types.FolderConfig) ([]string, gotenv.Env) {
		return []string{"snyk", "test", "--json"}, nil
	})

	require.Error(t, err)
	var cliErr *types.CliError
	require.ErrorAs(t, err, &cliErr)
	assert.Empty(t, cliErr.ErrorMessage)
	require.True(t, executor.waitCalled, "streaming CLI process must be waited after stdout is decoded")
}

func TestLegacyScanStream_CapturesOnlyErrorPrefix(t *testing.T) {
	stream := newLegacyScanStream(&cli.StreamingResult{
		Stdout: io.NopCloser(strings.NewReader(strings.Repeat("x", 8*1024))),
		Wait:   func() error { return nil },
	}, []string{"snyk", "test", "--json"})

	_, err := io.Copy(io.Discard, stream)

	require.NoError(t, err)
	require.Len(t, stream.capturedOutput(), maxCliScannerErrorOutputBytes)
}

func TestLegacyScanStream_FinishClosesStdoutBeforeWait(t *testing.T) {
	stdout := newCloseUnblocksReadCloser()
	waitStarted := make(chan struct{})
	done := make(chan error, 1)
	var waitStartedOnce sync.Once

	stream := &legacyScanStream{
		stdout: stdout,
		reader: stdout,
		wait: func() error {
			waitStartedOnce.Do(func() { close(waitStarted) })
			<-stdout.closed
			return nil
		},
		capturedBytes: &cappedByteBuffer{limit: maxCliScannerErrorOutputBytes},
		cmd:           []string{"snyk", "test", "--json"},
	}

	go func() {
		done <- stream.finish()
	}()

	require.Eventually(t, func() bool {
		select {
		case <-waitStarted:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(100 * time.Millisecond):
		_ = stdout.Close()
		err := <-done
		require.NoError(t, err)
		require.Fail(t, "finish must close stdout before waiting for the process")
	}
}

type closeUnblocksReadCloser struct {
	closed chan struct{}
	once   sync.Once
}

func newCloseUnblocksReadCloser() *closeUnblocksReadCloser {
	return &closeUnblocksReadCloser{closed: make(chan struct{})}
}

func (r *closeUnblocksReadCloser) Read(_ []byte) (int, error) {
	<-r.closed
	return 0, io.EOF
}

func (r *closeUnblocksReadCloser) Close() error {
	r.once.Do(func() { close(r.closed) })
	return nil
}

type streamingExecutorForLegacyScanTest struct {
	stdout     io.ReadCloser
	waitErr    error
	streamUsed bool
	waitCalled bool
}

func (e *streamingExecutorForLegacyScanTest) Execute(context.Context, []string, types.FilePath, gotenv.Env) ([]byte, error) {
	return nil, errors.New("buffered Execute should not be used for legacy OSS scan")
}

func (e *streamingExecutorForLegacyScanTest) ExecuteStreaming(context.Context, []string, types.FilePath, gotenv.Env) (*cli.StreamingResult, error) {
	e.streamUsed = true
	return &cli.StreamingResult{
		Stdout: e.stdout,
		Wait: func() error {
			e.waitCalled = true
			return e.waitErr
		},
	}, nil
}

func (e *streamingExecutorForLegacyScanTest) ExpandParametersFromConfig(base []string, _ *types.FolderConfig) []string {
	return base
}

func newHandleErrorTestScanner(t *testing.T, engine workflow.Engine) *CLIScanner {
	t.Helper()
	return &CLIScanner{
		IssueCache:       issuecache.NewIssueCacheForProduct(engine, product.ProductOpenSource),
		engine:           engine,
		cli:              cli.NewTestExecutorWithResponse(engine, "{}"),
		instrumentor:     performance.NewInstrumentor(),
		errorReporter:    error_reporting.NewTestErrorReporter(engine),
		learnService:     mock_learn.NewMockService(gomock.NewController(t)),
		notifier:         notification.NewMockNotifier(),
		configResolver:   defaultResolver(t, engine),
		mutex:            &sync.RWMutex{},
		inlineValueMutex: &sync.RWMutex{},
		packageScanMutex: &sync.Mutex{},
		scheduledScanMtx: &sync.Mutex{},
		runningScans:     make(map[types.FilePath]*scans.ScanProgress),
		supportedFiles:   make(map[string]bool),
	}
}

func commandExitError(t *testing.T, code int) error {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestCommandExitHelperProcess", "--", strconv.Itoa(code))
	cmd.Env = append(os.Environ(), "SNYK_LS_WANT_EXIT_HELPER=1")
	err := cmd.Run()
	require.Error(t, err)
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	return err
}

func TestCommandExitHelperProcess(t *testing.T) {
	if os.Getenv("SNYK_LS_WANT_EXIT_HELPER") != "1" {
		return
	}
	code, err := strconv.Atoi(os.Args[len(os.Args)-1])
	require.NoError(t, err)
	os.Exit(code)
}

func TestCLIScanner_unmarshallAndRetrieveAnalysis_referenceScanDoesNotReplaceIssueCache(t *testing.T) {
	engine := testutil.UnitTest(t)
	log := zerolog.Nop()
	baseCtx := ctx2.NewContextWithLogger(t.Context(), &log)
	baseCtx = ctx2.NewContextWithDependencies(baseCtx, map[string]any{ctx2.DepEngine: engine})

	newScanner := func() *CLIScanner {
		return &CLIScanner{
			IssueCache:       issuecache.NewIssueCacheForProduct(engine, product.ProductOpenSource),
			engine:           engine,
			cli:              cli.NewTestExecutorWithResponse(engine, "{}"),
			instrumentor:     performance.NewInstrumentor(),
			errorReporter:    error_reporting.NewTestErrorReporter(engine),
			learnService:     mock_learn.NewMockService(gomock.NewController(t)),
			notifier:         notification.NewMockNotifier(),
			configResolver:   testutil.DefaultConfigResolver(engine),
			mutex:            &sync.RWMutex{},
			inlineValueMutex: &sync.RWMutex{},
			packageScanMutex: &sync.Mutex{},
			runningScans:     make(map[types.FilePath]*scans.ScanProgress),
			supportedFiles:   map[string]bool{"package.json": true},
		}
	}

	filePath := types.FilePath("/tmp/wd/package.json")
	folderConfig := &types.FolderConfig{FolderPath: "/tmp/wd"}

	t.Run("reference scan does not clear IssueCache", func(t *testing.T) {
		cliScanner := newScanner()
		cliScanner.AddToCache([]types.Issue{
			&snyk.Issue{
				ID:               "id-1",
				AffectedFilePath: filePath,
				Product:          product.ProductOpenSource,
				AdditionalData:   snyk.OssIssueData{Key: "oss-key-1"},
			},
		})

		refCtx := ctx2.NewContextWithDeltaScanType(baseCtx, ctx2.Reference)
		refCtx = ctx2.NewContextWithWorkDirAndFilePath(refCtx, "/tmp/wd", filePath)
		refCtx = ctx2.NewContextWithFolderConfig(refCtx, folderConfig)

		_, _ = cliScanner.unmarshallAndRetrieveAnalysis(refCtx, []byte{}, "/tmp/wd", filePath, "text")
		require.Len(t, cliScanner.IssuesForFile(filePath), 1)
	})

	t.Run("working directory scan replaces cache with empty snapshot", func(t *testing.T) {
		cliScanner := newScanner()
		cliScanner.AddToCache([]types.Issue{
			&snyk.Issue{
				ID:               "id-1",
				AffectedFilePath: filePath,
				Product:          product.ProductOpenSource,
				AdditionalData:   snyk.OssIssueData{Key: "oss-key-1"},
			},
		})

		wdCtx := ctx2.NewContextWithDeltaScanType(baseCtx, ctx2.WorkingDirectory)
		wdCtx = ctx2.NewContextWithWorkDirAndFilePath(wdCtx, "/tmp/wd", filePath)
		wdCtx = ctx2.NewContextWithFolderConfig(wdCtx, folderConfig)

		_, _ = cliScanner.unmarshallAndRetrieveAnalysis(wdCtx, []byte{}, "/tmp/wd", filePath, "text")
		require.Len(t, cliScanner.IssuesForFile(filePath), 0)
	})

	t.Run("working directory scan does not wipe sibling workspace folders", func(t *testing.T) {
		cliScanner := newScanner()

		folderAFile := types.FilePath("/tmp/folderA/package.json")
		folderBFile := types.FilePath("/tmp/folderB/package.json")

		cliScanner.AddToCache([]types.Issue{
			&snyk.Issue{
				ID:               "id-folderA",
				AffectedFilePath: folderAFile,
				Product:          product.ProductOpenSource,
				AdditionalData:   snyk.OssIssueData{Key: "oss-folderA"},
			},
			&snyk.Issue{
				ID:               "id-folderB",
				AffectedFilePath: folderBFile,
				Product:          product.ProductOpenSource,
				AdditionalData:   snyk.OssIssueData{Key: "oss-folderB"},
			},
		})

		// Working-directory scan of folderB must only clear folderB entries; folderA must
		// remain because the CLIScanner is a singleton shared by every workspace folder.
		folderBConfig := &types.FolderConfig{FolderPath: "/tmp/folderB"}
		wdCtx := ctx2.NewContextWithDeltaScanType(baseCtx, ctx2.WorkingDirectory)
		wdCtx = ctx2.NewContextWithWorkDirAndFilePath(wdCtx, "/tmp/folderB", folderBFile)
		wdCtx = ctx2.NewContextWithFolderConfig(wdCtx, folderBConfig)

		_, _ = cliScanner.unmarshallAndRetrieveAnalysis(wdCtx, []byte{}, "/tmp/folderB", folderBFile, "text")

		require.Len(t, cliScanner.IssuesForFile(folderAFile), 1, "folderA OSS issues must survive a folderB scan")
		require.Len(t, cliScanner.IssuesForFile(folderBFile), 0, "folderB issues must be replaced by the empty WD snapshot")
	})
}

func Test_shouldUseLegacyScan(t *testing.T) {
	t.Run("legacy when SNYK_FORCE_LEGACY_CLI set", func(t *testing.T) {
		t.Setenv("SNYK_FORCE_LEGACY_CLI", "1")
		fc := folderConfigWithFlags(map[string]bool{featureflag.UseOsTest: true})
		useLegacy, reason := shouldUseLegacyScan(fc, []string{"snyk", "test"})
		assert.True(t, useLegacy)
		assert.Contains(t, reason, "SNYK_FORCE_LEGACY_CLI")
	})
	t.Run("legacy when --unmanaged flag", func(t *testing.T) {
		fc := folderConfigWithFlags(map[string]bool{featureflag.UseOsTest: true})
		useLegacy, reason := shouldUseLegacyScan(fc, []string{"snyk", "test", "--unmanaged"})
		assert.True(t, useLegacy)
		assert.Contains(t, reason, "--unmanaged")
	})
	t.Run("legacy when no new features required", func(t *testing.T) {
		fc := folderConfigWithFlags(map[string]bool{})
		useLegacy, reason := shouldUseLegacyScan(fc, []string{"snyk", "test"})
		assert.True(t, useLegacy)
		assert.Contains(t, reason, "no new features")
	})
	t.Run("new flow when feature flags present", func(t *testing.T) {
		fc := folderConfigWithFlags(map[string]bool{featureflag.UseOsTest: true})
		dir := t.TempDir()
		useLegacy, reason := shouldUseLegacyScan(fc, []string{"snyk", "test", dir})
		assert.False(t, useLegacy)
		assert.Contains(t, reason, "ostest")
		assert.Contains(t, reason, featureflag.UseOsTest)
	})
	t.Run("force legacy overrides feature flags", func(t *testing.T) {
		t.Setenv("SNYK_FORCE_LEGACY_CLI", "true")
		fc := folderConfigWithFlags(map[string]bool{featureflag.UseOsTest: true, featureflag.UseExperimentalRiskScoreInCLI: true})
		useLegacy, _ := shouldUseLegacyScan(fc, []string{"snyk", "test"})
		assert.True(t, useLegacy)
	})
	t.Run("legacy-only flag overrides feature flags", func(t *testing.T) {
		fc := folderConfigWithFlags(map[string]bool{featureflag.UseOsTest: true})
		useLegacy, _ := shouldUseLegacyScan(fc, []string{"snyk", "test", "--print-graph"})
		assert.True(t, useLegacy)
	})
}
