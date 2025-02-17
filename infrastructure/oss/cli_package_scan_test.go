/*
 * © 2023 Snyk Limited
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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/maps"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/infrastructure/oss/parser"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestCLIScanner_ScanPackages_WithoutContent(t *testing.T) {
	c := testutil.UnitTest(t)

	testFilePath, scanner, cliExecutor := setupCLIScannerAsPackageScanner(t, c)

	scanner.ScanPackages(context.Background(), c, testFilePath, "")

	assert.Eventuallyf(t, func() bool { return len(scanner.inlineValues[testFilePath]) == 2 }, time.Second*5, 10*time.Millisecond, "expected 2 values, got %d", len(scanner.inlineValues))
	assert.Len(t, scanner.packageIssueCache, 2)
	assert.NotContainsf(t, cliExecutor.GetCommand(), "--all-projects", "expected --all-projects NOT to be set")
}

func TestCLIScanner_ScanPackages_WithContent(t *testing.T) {
	c := testutil.UnitTest(t)

	testFilePath, scanner, _ := setupCLIScannerAsPackageScanner(t, c)

	bytes, err := os.ReadFile(string(testFilePath))
	fileContent := string(bytes)
	assert.NoError(t, err)

	scanner.ScanPackages(context.Background(), c, testFilePath, fileContent)

	assert.Len(t, scanner.inlineValues[testFilePath], 2)
	assert.Len(t, scanner.packageIssueCache, 2)
}

func TestCLIScanner_ScanPackages_WithContentAndNotSupportedFileExtension(t *testing.T) {
	c := testutil.UnitTest(t)

	testFilePath, scanner, _ := setupCLIScannerAsPackageScanner(t, c)

	bytes, err := os.ReadFile(string(testFilePath))
	fileContent := string(bytes)
	assert.NoError(t, err)

	scanner.ScanPackages(context.Background(), c, "test.php", fileContent)

	assert.Len(t, scanner.inlineValues, 0)
	assert.Len(t, scanner.packageIssueCache, 0)
}

func TestCLIScanner_isPackageScanSupported_Positive(t *testing.T) {
	c := testutil.UnitTest(t)
	_, cliScanner, _ := setupCLIScannerAsPackageScanner(t, c)

	assert.True(t, cliScanner.isPackageScanSupported("test.html"))
	assert.True(t, cliScanner.isPackageScanSupported("test.htm"))
}
func TestCLIScanner_isPackageScanSupported_Negative(t *testing.T) {
	c := testutil.UnitTest(t)
	_, cliScanner, _ := setupCLIScannerAsPackageScanner(t, c)

	assert.False(t, cliScanner.isPackageScanSupported("test.php"))
}

func TestCLIScanner_updateCachedDependencies_returns_not_cached_deps(t *testing.T) {
	c := testutil.UnitTest(t)
	_, cliScanner, _ := setupCLIScannerAsPackageScanner(t, c)

	dependencies := []parser.Dependency{
		{
			ArtifactID: "test",
			Version:    "1.0.0",
		},
		{
			ArtifactID: "test2",
			Version:    "2.0.0",
		},
	}

	notCached := cliScanner.updateCachedDependencies(dependencies)

	assert.Len(t, notCached, 2)
}

func TestCLIScanner_updateCachedDependencies_updates_range_of_issues_in_cache(t *testing.T) {
	c := testutil.UnitTest(t)
	testFilePath, cliScanner, _ := setupCLIScannerAsPackageScanner(t, c)

	// first (=cache deps)
	cliScanner.ScanPackages(context.Background(), c, testFilePath, "")
	dependencies, err := cliScanner.getDependencies(c, testFilePath, "")
	assert.NoError(t, err)
	assert.NotEmpty(t, dependencies)

	assert.Len(t, cliScanner.updateCachedDependencies(dependencies), 1)

	bytes, err := os.ReadFile(string(testFilePath))
	assert.NoError(t, err)

	// this should move the range of the issue in the cache down
	fileContent := "\n\n\n\n" + string(bytes)

	updatedDependencies, err := cliScanner.getDependencies(c, testFilePath, fileContent)
	assert.NoError(t, err)
	assert.NotEmpty(t, updatedDependencies)

	// we need to copy the cache to a different map because updateCachedDependencies will
	// change the range of the issues in the map, which is a pointer
	oldPackageCache := make(map[string][]types.Issue)
	maps.Copy(oldPackageCache, cliScanner.packageIssueCache)

	assert.Len(t, cliScanner.updateCachedDependencies(updatedDependencies), 1)

	for key, issues := range oldPackageCache {
		newIssues := cliScanner.packageIssueCache[key]
		for i, issue := range issues {
			assert.NotEqual(t, issue, newIssues[i])
			assert.Equal(t, issue.GetID(), newIssues[i].GetID())
			assert.Equal(t, issue.GetRange().Start.Line, newIssues[i].GetRange().Start.Line-4)
			assert.Equal(t, issue.GetRange().End.Line, newIssues[i].GetRange().End.Line-4)
		}
	}
}

func setupCLIScannerAsPackageScanner(t *testing.T, c *config.Config) (types.FilePath, *CLIScanner, *cli.TestExecutor) {
	t.Helper()
	c.SetCliSettings(&config.CliSettings{
		AdditionalOssParameters: []string{"--all-projects"},
		C:                       c,
	})
	notifier := notification.NewMockNotifier()
	instrumentor := performance.NewInstrumentor()
	errorReporter := error_reporting.NewTestErrorReporter()
	testDir := "testdata"
	testFilePath, err := filepath.Abs(filepath.Join(testDir, "test.html"))
	assert.NoError(t, err)
	testResult, err := filepath.Abs(filepath.Join(testDir, "packageScanTestHtmlOutput.json"))
	assert.NoError(t, err)
	cliExecutor := cli.NewTestExecutorWithResponseFromFile(testResult, c.Logger())
	scanner := NewCLIScanner(c, instrumentor, errorReporter, cliExecutor, getLearnMock(t), notifier).(*CLIScanner)
	return types.FilePath(testFilePath), scanner, cliExecutor
}
