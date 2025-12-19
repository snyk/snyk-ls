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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/learn/mock_learn"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/scans"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

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
			c := testutil.UnitTest(t)
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
				c.Logger(),
				filepath.Join(base, adjustedPath),
				tc.displayTargetFile,
				types.FilePath(filepath.Join(base, adjustedWorkDir)),
				types.FilePath(filepath.Join(base, adjustedPath)),
			)
			assert.Equal(t, expected, actual)
		})
	}
}

func TestCLIScanner_prepareScanCommand_RemovesAllProjectsParam(t *testing.T) {
	// Create a mock config
	c := testutil.UnitTest(t)

	// Setup test CLI executor
	cliExecutor := cli.NewTestExecutorWithResponse(c, "{}")

	// Setup the scanner with necessary dependencies
	instrumentor := performance.NewInstrumentor()
	errorReporter := error_reporting.NewTestErrorReporter()
	learnMock := mock_learn.NewMockService(gomock.NewController(t))
	notifier := notification.NewMockNotifier()

	cliScanner := &CLIScanner{
		config:            c,
		cli:               cliExecutor,
		instrumentor:      instrumentor,
		errorReporter:     errorReporter,
		learnService:      learnMock,
		notifier:          notifier,
		mutex:             &sync.RWMutex{},
		inlineValueMutex:  &sync.RWMutex{},
		packageScanMutex:  &sync.Mutex{},
		runningScans:      make(map[types.FilePath]*scans.ScanProgress),
		supportedFiles:    make(map[string]bool),
		packageIssueCache: make(map[string][]types.Issue),
	}

	// Test case 1: Command contains --all-projects, should remove it initially
	t.Run("removes --all-projects from command", func(t *testing.T) {
		// Setup command with --all-projects
		initialArgs := []string{"--all-projects"}
		parameterBlacklist := map[string]bool{}
		path := types.FilePath("/path/to/project")

		// Call the method under test
		result, _ := cliScanner.prepareScanCommand(initialArgs, parameterBlacklist, path, nil)

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
		// Create a new config with conflicting parameters
		configWithConflicts := testutil.UnitTest(t)

		// Set conflicting parameters directly in the CLI settings
		clisettings := configWithConflicts.CliSettings()
		clisettings.AdditionalOssParameters = []string{"--file=package.json"}

		// Update the scanner to use our new Config
		originalConfig := cliScanner.config
		cliScanner.config = configWithConflicts

		// Setup command with --all-projects
		initialArgs := []string{"--all-projects"}
		parameterBlacklist := map[string]bool{}
		path := types.FilePath("/path/to/project")

		// Call the method under test
		result, _ := cliScanner.prepareScanCommand(initialArgs, parameterBlacklist, path, nil)

		// Verify that --all-projects was removed and not added back due to conflict
		containsAllProjects := false
		for _, arg := range result {
			if arg == "--all-projects" {
				containsAllProjects = true
				break
			}
		}
		assert.False(t, containsAllProjects, "--all-projects should not be present when there are conflicting parameters")
		assert.Contains(t, result, "--file=package.json", "The conflicting parameter should be present")

		// Restore the original config to avoid affecting other tests
		cliScanner.config = originalConfig
	})

	// Test case 3: Command with a parameter that disables --all-projects (but is not itself filtered)
	t.Run("does not append --all-projects when --all-sub-projects is present", func(t *testing.T) {
		configWithConflicts := testutil.UnitTest(t)
		clisettings := configWithConflicts.CliSettings()
		clisettings.AdditionalOssParameters = []string{"--all-sub-projects"}

		originalConfig := cliScanner.config
		cliScanner.config = configWithConflicts
		defer func() { cliScanner.config = originalConfig }()

		initialArgs := []string{}
		parameterBlacklist := map[string]bool{}
		path := types.FilePath("/path/to/project")

		result, _ := cliScanner.prepareScanCommand(initialArgs, parameterBlacklist, path, nil)

		assert.NotContains(t, result, "--all-projects", "--all-projects should not be present when --all-sub-projects is present")
		assert.Contains(t, result, "--all-sub-projects", "--all-sub-projects should be present")
	})
}

func TestConvertScanResultToIssues_IgnoredIssuesNotPropagated(t *testing.T) {
	// Create a mock config
	c := testutil.UnitTest(t)

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
	errorReporter := error_reporting.NewTestErrorReporter()

	// Expect GetLesson to be called for the non-ignored issue (SNYK-1) when there's no AST node
	learnService.EXPECT().
		GetLesson("", "SNYK-1", nil, nil, types.DependencyVulnerability).
		Return(&learn.Lesson{Url: "https://learn.snyk.io/lesson/test"}, nil).
		AnyTimes()

	// Empty package issue cache
	packageIssueCache := make(map[string][]types.Issue)

	// Convert scan results to issues
	issues := convertScanResultToIssues(c, scanResult, workDir, targetFilePath, fileContent, learnService, errorReporter, packageIssueCache, c.Format())

	// Verify that only non-ignored issues are included in the result
	assert.Equal(t, 1, len(issues), "Expected only one non-ignored issue")

	// Get the issue and verify it's the non-ignored one
	issue, ok := issues[0].(*snyk.Issue)
	require.True(t, ok, "Expected issue to be of type *snyk.Issue")
	assert.Equal(t, "SNYK-1", issue.ID, "Expected the non-ignored issue ID")

	// Also verify the package issue cache only contains the non-ignored issue
	packageKey := "package1@1.0.0"
	cachedIssues, exists := packageIssueCache[packageKey]
	assert.True(t, exists, "Expected the package issue cache to contain the non-ignored issue")
	assert.Equal(t, 1, len(cachedIssues), "Expected one issue in the package issue cache")

	// Verify that the ignored issue's package key doesn't exist in the cache
	ignoredPackageKey := "package2@2.0.0"
	_, ignoredExists := packageIssueCache[ignoredPackageKey]
	assert.False(t, ignoredExists, "Expected the ignored issue to not be in the package issue cache")
}
