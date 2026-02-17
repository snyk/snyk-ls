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

package workspace

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/puzpuzpuz/xsync/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/domain/snyk/persistence/mock_persistence"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	context2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

func Test_Scan_WhenNoIssues_shouldNotProcessResults(t *testing.T) {
	hoverRecorder := hover.NewFakeHoverService()
	c := testutil.UnitTest(t)
	f := NewFolder(c, "dummy", "dummy", scanner.NewTestScanner(), hoverRecorder, scanner.NewMockScanNotifier(), notification.NewMockNotifier(), persistence.NewNopScanPersister(), scanstates.NewNoopStateAggregator(), featureflag.NewFakeService(), nil)

	data := types.ScanData{
		Product:           "",
		Issues:            []types.Issue{},
		UpdateGlobalCache: true,
		SendAnalytics:     true,
	}
	f.ProcessResults(t.Context(), data)

	assert.Equal(t, 0, hoverRecorder.Calls())
}

func Test_ProcessResults_whenDifferentPaths_AddsToCache(t *testing.T) {
	c := testutil.UnitTest(t)
	notifier := notification.NewMockNotifier()
	f := NewMockFolder(c, notifier)
	setupWorkspaceWithFolder(c, f, notifier)

	path1 := types.FilePath(filepath.Join(string(f.path), "path1"))
	path2 := types.FilePath(filepath.Join(string(f.path), "path2"))
	data := types.ScanData{
		Product: product.ProductOpenSource,
		Issues: []types.Issue{
			testutil.NewMockIssue("id1", path1),
			testutil.NewMockIssue("id2", path2),
		},
		UpdateGlobalCache: true,
		SendAnalytics:     true,
	}
	f.ScanFolder(t.Context())
	f.ProcessResults(t.Context(), data)

	assert.Equal(t, 2, f.documentDiagnosticCache.Size())
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, path1))
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, path2))
	assert.Len(t, GetValueFromMap(f.documentDiagnosticCache, path1), 1)
	assert.Len(t, GetValueFromMap(f.documentDiagnosticCache, path2), 1)
}

func Test_ProcessResults_whenSamePaths_AddsToCache(t *testing.T) {
	c := testutil.UnitTest(t)
	notifier := notification.NewMockNotifier()
	f := NewMockFolder(c, notifier)
	setupWorkspaceWithFolder(c, f, notifier)

	filePath := types.FilePath("dummy/path1")
	data := types.ScanData{
		Product: product.ProductOpenSource,
		Issues: []types.Issue{
			testutil.NewMockIssue("id1", filePath),
			testutil.NewMockIssue("id2", filePath),
		},
		UpdateGlobalCache: true,
		SendAnalytics:     true,
	}
	f.ProcessResults(t.Context(), data)

	assert.Equal(t, 1, len(f.Issues()))
	assert.Len(t, f.IssuesForFile(filePath), 2)
}

func Test_ProcessResults_whenDifferentPaths_AccumulatesIssues(t *testing.T) {
	c := testutil.UnitTest(t)
	notifier := notification.NewMockNotifier()
	f := NewMockFolder(c, notifier)
	setupWorkspaceWithFolder(c, f, notifier)

	path1 := types.FilePath(filepath.Join(string(f.path), "path1"))
	path2 := types.FilePath(filepath.Join(string(f.path), "path2"))
	path3 := types.FilePath(filepath.Join(string(f.path), "path3"))
	data := types.ScanData{
		Product: product.ProductOpenSource,
		Issues: []types.Issue{
			testutil.NewMockIssue("id1", path1),
			testutil.NewMockIssue("id2", path2),
			testutil.NewMockIssue("id3", path3),
		},
		UpdateGlobalCache: true,
		SendAnalytics:     true,
	}
	f.ProcessResults(t.Context(), data)

	assert.Len(t, f.Issues(), 3)
	assert.Len(t, f.IssuesForFile(path1), 1)
	assert.Len(t, f.IssuesForFile(path2), 1)
	assert.Len(t, f.IssuesForFile(path3), 1)
}

func Test_ProcessResults_whenSamePaths_AccumulatesIssues(t *testing.T) {
	c := testutil.UnitTest(t)
	notifier := notification.NewMockNotifier()
	f := NewMockFolder(c, notifier)
	setupWorkspaceWithFolder(c, f, notifier)

	path1 := types.FilePath(filepath.Join(string(f.path), "path1"))
	data := types.ScanData{
		Product: product.ProductOpenSource,
		Issues: []types.Issue{
			testutil.NewMockIssue("id1", path1),
			testutil.NewMockIssue("id2", path1),
			testutil.NewMockIssue("id3", path1),
		},
		UpdateGlobalCache: true,
		SendAnalytics:     true,
	}
	f.ProcessResults(t.Context(), data)

	assert.Len(t, f.Issues(), 1)
	issuesForFile := f.IssuesForFile(path1)
	assert.NotNil(t, issuesForFile)
	assert.Len(t, issuesForFile, 3)
}

func Test_ProcessResults_whenSamePathsAndDuplicateIssues_DeDuplicates(t *testing.T) {
	c := testutil.UnitTest(t)
	notifier := notification.NewMockNotifier()
	f := NewMockFolder(c, notifier)
	setupWorkspaceWithFolder(c, f, notifier)

	path1 := types.FilePath(filepath.Join(string(f.path), "path1"))
	path2 := types.FilePath(filepath.Join(string(f.path), "path2"))
	issue1 := testutil.NewMockIssue("id1", path1)
	issue2 := testutil.NewMockIssue("id2", path1)
	issue3 := testutil.NewMockIssue("id3", path1)
	issue4 := testutil.NewMockIssue("id1", path2)
	issue5 := testutil.NewMockIssue("id3", path2)

	data := types.ScanData{
		Product: product.ProductOpenSource,
		Issues: []types.Issue{
			issue1,
			issue1,
			issue2,
			issue3,
			issue4,
			issue5,
		},
		UpdateGlobalCache: true,
		SendAnalytics:     true,
	}
	f.ProcessResults(t.Context(), data)

	assert.Len(t, f.Issues(), 2)
	issuesForFile := f.IssuesForFile(path1)
	assert.NotNil(t, issuesForFile)
	assert.Len(t, issuesForFile, 3)
}

func TestProcessResults_whenFilteringSeverity_ProcessesOnlyFilteredIssues(t *testing.T) {
	c := testutil.UnitTest(t)

	severityFilter := types.NewSeverityFilter(true, false, true, false)
	c.SetSeverityFilter(&severityFilter)

	notifier := notification.NewNotifier()
	f := NewMockFolder(c, notifier)
	setupWorkspaceWithFolder(c, f, notifier)

	path1 := types.FilePath(filepath.Join(string(f.path), "path1"))
	data := types.ScanData{
		Product: product.ProductOpenSource,
		Issues: []types.Issue{
			testutil.NewMockIssueWithSeverity("id1", types.FilePath(filepath.Join(string(f.path), string(path1))), types.Critical),
			testutil.NewMockIssueWithSeverity("id2", types.FilePath(filepath.Join(string(f.path), string(path1))), types.High),
			testutil.NewMockIssueWithSeverity("id3", types.FilePath(filepath.Join(string(f.path), string(path1))), types.Medium),
			testutil.NewMockIssueWithSeverity("id4", types.FilePath(filepath.Join(string(f.path), string(path1))), types.Low),
			testutil.NewMockIssueWithSeverity("id5", types.FilePath(filepath.Join(string(f.path), string(path1))), types.Critical),
		},
		UpdateGlobalCache: true,
		SendAnalytics:     true,
	}
	f.ProcessResults(t.Context(), data)

	mtx := &sync.Mutex{}
	var diagnostics []types.Diagnostic

	f.notifier.CreateListener(func(event any) {
		switch params := event.(type) {
		case types.PublishDiagnosticsParams:
			mtx.Lock()
			defer mtx.Unlock()
			diagnostics = params.Diagnostics
		}
	})

	assert.Eventually(
		t,
		func() bool {
			mtx.Lock()
			defer mtx.Unlock()

			hasCorrectIssues := len(diagnostics) == 3 && diagnostics[0].Code == "id1" && diagnostics[1].Code == "id3" && diagnostics[2].Code == "id5"
			return hasCorrectIssues
		},
		1*time.Second,
		10*time.Millisecond,
		"Expected to receive only critical issues",
	)
}

func TestProcessResults_whenFilteringIssueViewOptions_ProcessesOnlyFilteredIssues(t *testing.T) {
	c := testutil.UnitTest(t)

	issueViewOptions := types.NewIssueViewOptions(false, true)
	c.SetIssueViewOptions(&issueViewOptions)

	folderPath := types.FilePath("dummy")
	folderConfig := &types.FolderConfig{
		FolderPath: folderPath,
		FeatureFlags: map[string]bool{
			featureflag.SnykCodeConsistentIgnores: true,
		},
	}
	err := storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), folderConfig, c.Logger())
	require.NoError(t, err)

	notifier := notification.NewNotifier()
	f := NewFolder(c, folderPath, "dummy", scanner.NewTestScanner(), hover.NewFakeHoverService(), scanner.NewMockScanNotifier(), notifier, persistence.NewNopScanPersister(), scanstates.NewNoopStateAggregator(), featureflag.NewFakeService(), nil)

	path1 := types.FilePath(filepath.Join(string(f.path), "path1"))
	data := types.ScanData{
		Product: product.ProductOpenSource,
		Issues: []types.Issue{
			testutil.NewMockIssueWithIgnored("id1", types.FilePath(filepath.Join(string(f.path), string(path1))), true),
			testutil.NewMockIssueWithIgnored("id2", types.FilePath(filepath.Join(string(f.path), string(path1))), false),
			testutil.NewMockIssueWithIgnored("id3", types.FilePath(filepath.Join(string(f.path), string(path1))), true),
			testutil.NewMockIssueWithIgnored("id4", types.FilePath(filepath.Join(string(f.path), string(path1))), false),
			testutil.NewMockIssueWithIgnored("id5", types.FilePath(filepath.Join(string(f.path), string(path1))), true),
		},
		UpdateGlobalCache: true,
		SendAnalytics:     false,
	}

	f.ProcessResults(t.Context(), data)

	mtx := &sync.Mutex{}
	var diagnostics []types.Diagnostic

	f.notifier.CreateListener(func(event any) {
		switch params := event.(type) {
		case types.PublishDiagnosticsParams:
			mtx.Lock()
			defer mtx.Unlock()
			diagnostics = params.Diagnostics
		}
	})

	assert.Eventually(
		t,
		func() bool {
			mtx.Lock()
			defer mtx.Unlock()

			hasCorrectIssues := len(diagnostics) == 3 && diagnostics[0].Code == "id1" && diagnostics[1].Code == "id3" && diagnostics[2].Code == "id5"
			return hasCorrectIssues
		},
		1*time.Second,
		10*time.Millisecond,
		"Expected to receive only ignored issues",
	)
}

func Test_Clear(t *testing.T) {
	c := testutil.UnitTest(t)
	notifier := notification.NewNotifier()
	f := NewMockFolder(c, notifier)
	setupWorkspaceWithFolder(c, f, notifier)

	path1 := types.FilePath(filepath.Join(string(f.path), "path1"))
	path2 := types.FilePath(filepath.Join(string(f.path), "path2"))
	data := types.ScanData{
		Product: product.ProductOpenSource,
		Issues: []types.Issue{
			testutil.NewMockIssue("id1", path1),
			testutil.NewMockIssue("id2", path2),
		},
		UpdateGlobalCache: true,
		SendAnalytics:     true,
	}
	f.ProcessResults(t.Context(), data)
	mtx := &sync.Mutex{}
	clearDiagnosticNotifications := 0

	f.notifier.DisposeListener()
	f.notifier.CreateListener(func(event any) {
		switch params := event.(type) {
		case types.PublishDiagnosticsParams:
			if len(params.Diagnostics) == 0 {
				mtx.Lock()
				clearDiagnosticNotifications++
				mtx.Unlock()
			}
		}
	})

	f.Clear()

	assert.Equal(t, 0, f.documentDiagnosticCache.Size())
	assert.True(t, f.hoverService.(*hover.FakeHoverService).DeletedHovers[path1])
	assert.True(t, f.hoverService.(*hover.FakeHoverService).DeletedHovers[path2])
	assert.Eventually(
		t,
		func() bool {
			mtx.Lock()
			defer mtx.Unlock()
			return clearDiagnosticNotifications == 2
		},
		1*time.Second,
		10*time.Millisecond,
	)
	f.notifier.DisposeListener()
}

func Test_IsTrusted_shouldReturnFalseByDefault(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetTrustedFolderFeatureEnabled(true)
	f := NewMockFolder(c, notification.NewMockNotifier())
	assert.False(t, f.IsTrusted())
}

func Test_IsTrusted_shouldReturnTrueForPathContainedInTrustedFolders(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetTrustedFolderFeatureEnabled(true)
	c.SetTrustedFolders([]types.FilePath{"dummy"})
	f := NewMockFolder(c, notification.NewMockNotifier())
	assert.True(t, f.IsTrusted())
}

func Test_IsTrusted_shouldReturnTrueForSubfolderOfTrustedFolders_Linux(t *testing.T) {
	c := testutil.IntegTest(t)
	testsupport.NotOnWindows(t, "Unix/macOS file paths are incompatible with Windows")
	c.SetTrustedFolderFeatureEnabled(true)
	c.SetTrustedFolders([]types.FilePath{"/dummy"})
	f := NewFolder(c, "/dummy/dummyF", "dummy", scanner.NewTestScanner(), hover.NewFakeHoverService(), scanner.NewMockScanNotifier(), notification.NewMockNotifier(), persistence.NewNopScanPersister(), scanstates.NewNoopStateAggregator(), featureflag.NewFakeService(), nil)
	assert.True(t, f.IsTrusted())
}

func Test_IsTrusted_shouldReturnFalseForDifferentFolder(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetTrustedFolderFeatureEnabled(true)
	c.SetTrustedFolders([]types.FilePath{"/dummy"})
	f := NewFolder(c, "/UntrustedPath", "dummy", scanner.NewTestScanner(), hover.NewFakeHoverService(), scanner.NewMockScanNotifier(), notification.NewMockNotifier(), persistence.NewNopScanPersister(), scanstates.NewNoopStateAggregator(), featureflag.NewFakeService(), nil)
	assert.False(t, f.IsTrusted())
}

func Test_IsTrusted_shouldReturnTrueForSubfolderOfTrustedFolders(t *testing.T) {
	c := testutil.IntegTest(t)
	testsupport.OnlyOnWindows(t, "Windows specific test")
	c.SetTrustedFolderFeatureEnabled(true)
	c.SetTrustedFolders([]types.FilePath{"c:\\dummy"})
	f := NewFolder(c, "c:\\dummy\\dummyF", "dummy", scanner.NewTestScanner(), hover.NewFakeHoverService(), scanner.NewMockScanNotifier(), notification.NewMockNotifier(), persistence.NewNopScanPersister(), scanstates.NewNoopStateAggregator(), featureflag.NewFakeService(), nil)
	assert.True(t, f.IsTrusted())
}

func Test_IsTrusted_shouldReturnTrueIfTrustFeatureDisabled(t *testing.T) {
	c := testutil.UnitTest(t) // disables trust feature
	f := NewFolder(c, "c:\\dummy\\dummyF", "dummy", scanner.NewTestScanner(), hover.NewFakeHoverService(), scanner.NewMockScanNotifier(), notification.NewMockNotifier(), persistence.NewNopScanPersister(), scanstates.NewNoopStateAggregator(), featureflag.NewFakeService(), nil)
	assert.True(t, f.IsTrusted())
}

func Test_FilterCachedDiagnostics_filtersDisabledSeverity(t *testing.T) {
	c := testutil.UnitTest(t)

	// arrange
	filePath, folderPath := types.FilePath("test/path"), types.FilePath("test")

	criticalIssue := &snyk.Issue{
		AffectedFilePath: filePath,
		Severity:         types.Critical,
		Product:          product.ProductOpenSource,
		AdditionalData:   snyk.OssIssueData{Key: util.Result(uuid.NewUUID()).String()},
	}
	highIssue := &snyk.Issue{
		AffectedFilePath: filePath,
		Severity:         types.High,
		Product:          product.ProductOpenSource,
		AdditionalData:   snyk.OssIssueData{Key: util.Result(uuid.NewUUID()).String()},
	}
	mediumIssue := &snyk.Issue{
		AffectedFilePath: filePath,
		Severity:         types.Medium,
		Product:          product.ProductOpenSource,
		AdditionalData:   snyk.OssIssueData{Key: util.Result(uuid.NewUUID()).String()},
	}
	lowIssue := &snyk.Issue{
		AffectedFilePath: filePath,
		Severity:         types.Low,
		Product:          product.ProductOpenSource,
		AdditionalData:   snyk.OssIssueData{Key: util.Result(uuid.NewUUID()).String()},
	}

	scannerRecorder := scanner.NewTestScanner()
	scannerRecorder.Issues = []types.Issue{
		criticalIssue,
		highIssue,
		mediumIssue,
		lowIssue,
	}

	f := NewFolder(c, folderPath, "Test", scannerRecorder, hover.NewFakeHoverService(), scanner.NewMockScanNotifier(), notification.NewMockNotifier(), persistence.NewNopScanPersister(), scanstates.NewNoopStateAggregator(), featureflag.NewFakeService(), nil)
	ctx := t.Context()

	c.SetSeverityFilter(util.Ptr(types.NewSeverityFilter(true, true, false, false)))

	// act
	f.ScanFile(ctx, filePath)
	filteredDiagnostics := f.filterDiagnostics(f.Issues())

	// assert
	assert.Len(t, filteredDiagnostics[filePath], 2)
	assert.Contains(t, filteredDiagnostics[filePath], criticalIssue)
	assert.Contains(t, filteredDiagnostics[filePath], highIssue)
}

func Test_FilterCachedDiagnostics_filtersIgnoredIssues(t *testing.T) {
	c := testutil.UnitTest(t)

	// arrange
	filePath, folderPath := types.FilePath("test/path"), types.FilePath("test")

	folderConfig := &types.FolderConfig{
		FolderPath: folderPath,
		FeatureFlags: map[string]bool{
			featureflag.SnykCodeConsistentIgnores: true,
		},
	}
	err := storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), folderConfig, c.Logger())
	require.NoError(t, err)

	openIssue1 := &snyk.Issue{
		AffectedFilePath: filePath,
		IsIgnored:        false,
		Product:          product.ProductOpenSource,
		AdditionalData:   snyk.OssIssueData{Key: util.Result(uuid.NewUUID()).String()},
	}
	openIssue2 := &snyk.Issue{
		AffectedFilePath: filePath,
		IsIgnored:        false,
		Product:          product.ProductOpenSource,
		AdditionalData:   snyk.OssIssueData{Key: util.Result(uuid.NewUUID()).String()},
	}
	ignoredIssue1 := &snyk.Issue{
		AffectedFilePath: filePath,
		IsIgnored:        true,
		Product:          product.ProductOpenSource,
		AdditionalData:   snyk.OssIssueData{Key: util.Result(uuid.NewUUID()).String()},
	}
	ignoredIssue2 := &snyk.Issue{
		AffectedFilePath: filePath,
		IsIgnored:        true,
		Product:          product.ProductOpenSource,
		AdditionalData:   snyk.OssIssueData{Key: util.Result(uuid.NewUUID()).String()},
	}

	scannerRecorder := scanner.NewTestScanner()
	scannerRecorder.SendAnalytics = false
	scannerRecorder.Issues = []types.Issue{
		openIssue1,
		openIssue2,
		ignoredIssue1,
		ignoredIssue2,
	}

	f := NewFolder(c, folderPath, "Test", scannerRecorder, hover.NewFakeHoverService(), scanner.NewMockScanNotifier(), notification.NewMockNotifier(), persistence.NewNopScanPersister(), scanstates.NewNoopStateAggregator(), featureflag.NewFakeService(), nil)
	ctx := t.Context()

	c.SetIssueViewOptions(util.Ptr(types.NewIssueViewOptions(true, false)))

	// act
	f.ScanFile(ctx, filePath)
	filteredDiagnostics := f.filterDiagnostics(f.Issues())

	// assert
	assert.Len(t, filteredDiagnostics[filePath], 2)
	assert.Contains(t, filteredDiagnostics[filePath], openIssue1)
	assert.Contains(t, filteredDiagnostics[filePath], openIssue2)
}

func Test_FilterIssues_RiskScoreThreshold(t *testing.T) {
	// Shared setup for all subtests
	c := testutil.UnitTest(t)

	folderPath := types.FilePath(t.TempDir())
	engineConfig := c.Engine().GetConfiguration()
	logger := c.Logger()

	// Create minimal folder for testing FilterIssues
	sc := scanner.NewTestScanner()
	folder := NewFolder(c, folderPath, "test-folder", sc, hover.NewFakeHoverService(), scanner.NewMockScanNotifier(), notification.NewMockNotifier(), persistence.NewNopScanPersister(), scanstates.NewNoopStateAggregator(), featureflag.NewFakeService(), nil)

	filePath := types.FilePath(filepath.Join(string(folderPath), "test.go"))

	// Create issues with different risk scores
	issue1 := &snyk.Issue{
		ID:               "issue-1",
		AffectedFilePath: filePath,
		Severity:         types.High,
		Product:          product.ProductOpenSource,
		AdditionalData: snyk.OssIssueData{
			Key:       "issue-1-key",
			RiskScore: 300,
		},
	}

	issue2 := &snyk.Issue{
		ID:               "issue-2",
		AffectedFilePath: filePath,
		Severity:         types.High,
		Product:          product.ProductOpenSource,
		AdditionalData: snyk.OssIssueData{
			Key:       "issue-2-key",
			RiskScore: 500,
		},
	}

	issue3 := &snyk.Issue{
		ID:               "issue-3",
		AffectedFilePath: filePath,
		Severity:         types.High,
		Product:          product.ProductOpenSource,
		AdditionalData: snyk.OssIssueData{
			Key:       "issue-3-key",
			RiskScore: 600,
		},
	}

	supportedIssueTypes := map[product.FilterableIssueType]bool{
		product.FilterableIssueTypeOpenSource: true,
	}

	issuesByFile := snyk.IssuesByFile{
		filePath: {issue1, issue2, issue3},
	}

	t.Run("shows all issues when threshold is zero", func(t *testing.T) {
		// Set folder config with feature flag enabled
		folderConfig := &types.FolderConfig{
			FolderPath: folderPath,
			FeatureFlags: map[string]bool{
				featureflag.UseExperimentalRiskScoreInCLI: true, // The one we actually use.
				// featureflag.UseExperimentalRiskScore: true, // Not used in the prod filtering logic.
			},
		}
		err := storedconfig.UpdateFolderConfig(engineConfig, folderConfig, logger)
		require.NoError(t, err)

		// Set global risk score threshold to 0 (show all)
		c.SetRiskScoreThreshold(util.Ptr(0))

		// Verify all issues are visible when threshold is 0
		filteredIssues := folder.FilterIssues(issuesByFile, supportedIssueTypes)
		require.Contains(t, filteredIssues, filePath)
		assert.ElementsMatch(t, filteredIssues[filePath], []types.Issue{issue1, issue2, issue3}, "All issues should be visible when threshold is 0")
	})

	t.Run("filters issues by threshold", func(t *testing.T) {
		// Set folder config with feature flag enabled
		folderConfig := &types.FolderConfig{
			FolderPath: folderPath,
			FeatureFlags: map[string]bool{
				featureflag.UseExperimentalRiskScoreInCLI: true, // The one we actually use.
				// featureflag.UseExperimentalRiskScore: true, // Not used in the prod filtering logic.
			},
		}
		err := storedconfig.UpdateFolderConfig(engineConfig, folderConfig, logger)
		require.NoError(t, err)

		// Set global risk score threshold of 400
		c.SetRiskScoreThreshold(util.Ptr(400))

		// Verify filtering works correctly with threshold of 400
		filteredIssues := folder.FilterIssues(issuesByFile, supportedIssueTypes)
		require.Contains(t, filteredIssues, filePath)

		assert.Len(t, filteredIssues[filePath], 2, "Only issues with risk score >= 400 should be visible")
		assert.NotContains(t, filteredIssues[filePath], issue1, "Issue 1 (risk score 300) should be filtered out")
		assert.Contains(t, filteredIssues[filePath], issue2, "Issue 2 (risk score 500) should be visible")
		assert.Contains(t, filteredIssues[filePath], issue3, "Issue 3 (risk score 600) should be visible")
	})
}

func Test_FilterIssues_CombinedFiltering(t *testing.T) {
	c := testutil.UnitTest(t)

	folderPath := types.FilePath(t.TempDir())
	engineConfig := c.Engine().GetConfiguration()
	logger := c.Logger()

	// Set up folder config with feature flags enabled
	folderConfig := &types.FolderConfig{
		FolderPath: folderPath,
		FeatureFlags: map[string]bool{
			featureflag.UseExperimentalRiskScoreInCLI: true, // The one we actually use.
			// featureflag.UseExperimentalRiskScore: true, // Not used in the prod filtering logic.
			featureflag.SnykCodeConsistentIgnores: true,
		},
	}
	err := storedconfig.UpdateFolderConfig(engineConfig, folderConfig, logger)
	require.NoError(t, err)

	// Set global risk score threshold
	c.SetRiskScoreThreshold(util.Ptr(400))
	// Disable low severity in global config
	severityFilter := types.NewSeverityFilter(true, true, true, false)
	c.SetSeverityFilter(&severityFilter)
	// Only show open issues (not ignored)
	c.SetIssueViewOptions(util.Ptr(types.NewIssueViewOptions(true, false)))

	sc := scanner.NewTestScanner()
	folder := NewFolder(c, folderPath, "test-folder", sc, hover.NewFakeHoverService(), scanner.NewMockScanNotifier(), notification.NewMockNotifier(), persistence.NewNopScanPersister(), scanstates.NewNoopStateAggregator(), featureflag.NewFakeService(), nil)

	filePath := types.FilePath(filepath.Join(string(folderPath), "test.go"))

	// Issue that passes all filters (visible)
	visibleIssue := &snyk.Issue{
		ID:               "visible",
		AffectedFilePath: filePath,
		Severity:         types.High,
		IsIgnored:        false,
		Product:          product.ProductOpenSource,
		AdditionalData: snyk.OssIssueData{
			Key:       "visible-key",
			RiskScore: 500,
		},
	}

	// Issue filtered by unsupported type (IaC not in supportedIssueTypes)
	unsupportedTypeIssue := &snyk.Issue{
		ID:               "unsupported-type",
		AffectedFilePath: filePath,
		Severity:         types.High,
		Product:          product.ProductInfrastructureAsCode,
	}

	// Issue filtered by severity (Low severity disabled)
	lowSeverityIssue := &snyk.Issue{
		ID:               "low-severity",
		AffectedFilePath: filePath,
		Severity:         types.Low,
		Product:          product.ProductOpenSource,
		AdditionalData: snyk.OssIssueData{
			Key:       "low-severity-key",
			RiskScore: 500,
		},
	}

	// Issue filtered by risk score (below threshold of 400)
	lowRiskScoreIssue := &snyk.Issue{
		ID:               "low-risk-score",
		AffectedFilePath: filePath,
		Severity:         types.High,
		Product:          product.ProductOpenSource,
		AdditionalData: snyk.OssIssueData{
			Key:       "low-risk-key",
			RiskScore: 300,
		},
	}

	// Issue filtered by issue view options (ignored issue when only showing open)
	ignoredIssue := &snyk.Issue{
		ID:               "ignored",
		AffectedFilePath: filePath,
		Severity:         types.High,
		IsIgnored:        true,
		Product:          product.ProductOpenSource,
		AdditionalData: snyk.OssIssueData{
			Key:       "ignored-key",
			RiskScore: 500,
		},
	}

	supportedIssueTypes := map[product.FilterableIssueType]bool{
		product.FilterableIssueTypeOpenSource: true,
		// IaC intentionally not included to test unsupported type filtering
	}

	issuesByFile := snyk.IssuesByFile{
		filePath: {visibleIssue, unsupportedTypeIssue, lowSeverityIssue, lowRiskScoreIssue, ignoredIssue},
	}

	// Test FilterIssues returns only the visible issue
	// All other issues should be filtered for their respective reasons
	filteredIssues := folder.FilterIssues(issuesByFile, supportedIssueTypes)
	require.Contains(t, filteredIssues, filePath)

	// Only the visible issue should pass all filters
	assert.Len(t, filteredIssues[filePath], 1, "Only one issue should be visible (4 filtered: unsupported type, severity, risk score, issue view options)")
	assert.Contains(t, filteredIssues[filePath], visibleIssue, "Issue passing all filters should be visible")
	assert.NotContains(t, filteredIssues[filePath], unsupportedTypeIssue, "IaC issue should be filtered (unsupported type)")
	assert.NotContains(t, filteredIssues[filePath], lowSeverityIssue, "Low severity issue should be filtered (severity filter)")
	assert.NotContains(t, filteredIssues[filePath], lowRiskScoreIssue, "Low risk score issue should be filtered (risk score threshold)")
	assert.NotContains(t, filteredIssues[filePath], ignoredIssue, "Ignored issue should be filtered (issue view options)")
}

func Test_ClearDiagnosticsByIssueType(t *testing.T) {
	// Arrange
	c := testutil.UnitTest(t)
	notifier := notification.NewMockNotifier()
	f := NewMockFolder(c, notifier)
	setupWorkspaceWithFolder(c, f, notifier)
	filePath := types.FilePath(filepath.Join(string(f.path), "path1"))
	mockOpenSourceIssue := testutil.NewMockIssue("id1", filePath)
	removedIssueType := product.FilterableIssueTypeOpenSource
	mockOpenSourceIssue.Product = product.ProductOpenSource
	mockIacIssue := testutil.NewMockIssue("id2", filePath)
	mockIacIssue.Product = product.ProductInfrastructureAsCode
	data := types.ScanData{
		Product: product.ProductOpenSource,
		Issues: []types.Issue{
			mockIacIssue,
			mockOpenSourceIssue,
		},
		UpdateGlobalCache: true,
		SendAnalytics:     true,
	}
	f.ProcessResults(t.Context(), data)
	const expectedIssuesCountAfterRemoval = 1

	// Act
	f.ClearDiagnosticsByIssueType(removedIssueType)

	// Assert
	issues := f.IssuesForFile(filePath)
	t.Run("Does not return diagnostics of that type", func(t *testing.T) {
		for _, issue := range issues {
			assert.NotEqual(t, removedIssueType, issue.GetProduct())
		}
	})

	t.Run("Return diagnostics of other types", func(t *testing.T) {
		assert.Len(t, issues, expectedIssuesCountAfterRemoval)
	})
}

func Test_processResults_ShouldSendSuccess(t *testing.T) {
	// Arrange
	c := testutil.UnitTest(t)

	notifier := notification.NewMockNotifier()
	f, scanNotifier := NewMockFolderWithScanNotifier(c, notifier)
	setupWorkspaceWithFolder(c, f, notifier)
	var path = "path1"
	mockCodeIssue := testutil.NewMockIssue("id1", types.FilePath(filepath.Join(string(f.path), path)))

	data := types.ScanData{
		Product:           product.ProductOpenSource,
		Issues:            []types.Issue{mockCodeIssue},
		UpdateGlobalCache: true,
		SendAnalytics:     true,
	}
	// Act
	f.ProcessResults(t.Context(), data)

	// Assert
	assert.Len(t, scanNotifier.SuccessCalls(), 1)
}

func Test_processResults_ShouldSendError(t *testing.T) {
	// Arrange
	c := testutil.UnitTest(t)

	notifier := notification.NewMockNotifier()
	f, scanNotifier := NewMockFolderWithScanNotifier(c, notifier)
	setupWorkspaceWithFolder(c, f, notifier)
	const filePath = "path1"
	mockCodeIssue := testutil.NewMockIssue("id1", filePath)

	data := types.ScanData{
		Product: product.ProductOpenSource,
		Issues: []types.Issue{
			mockCodeIssue,
		},
		UpdateGlobalCache: true,
		SendAnalytics:     true,
		Err:               errors.New("test error"),
	} // Act
	f.ProcessResults(t.Context(), data)

	// Assert
	assert.Empty(t, scanNotifier.SuccessCalls())
	assert.Len(t, scanNotifier.ErrorCalls(), 1)
}

func Test_processResults_ShouldSendAnalyticsToAPI(t *testing.T) {
	c := testutil.UnitTest(t)

	engineMock, gafConfig := testutil.SetUpEngineMock(t, c)

	engineMock.EXPECT().GetWorkflows().AnyTimes()

	notifier := notification.NewNotifier()
	f, _ := NewMockFolderWithScanNotifier(c, notifier)
	setupWorkspaceWithFolder(c, f, notifier)

	const testFolderOrg = "test-org"
	err := storedconfig.UpdateFolderConfig(gafConfig, &types.FolderConfig{
		FolderPath:                  f.path,
		PreferredOrg:                testFolderOrg,
		OrgSetByUser:                true,
		OrgMigratedFromGlobalConfig: true,
	}, c.Logger())
	require.NoError(t, err)

	filePath := types.FilePath(filepath.Join(string(f.path), "path1"))
	mockCodeIssue := testutil.NewMockIssue("id1", filePath)

	data := types.ScanData{
		Product:           product.ProductOpenSource,
		Issues:            []types.Issue{mockCodeIssue},
		Path:              f.path,
		UpdateGlobalCache: true,
		SendAnalytics:     true,
	}

	ic := analytics.NewInstrumentationCollector()

	ua := util.GetUserAgent(gafConfig, config.Version)
	ic.SetUserAgent(ua)
	categories := setupCategories(&data, c)
	ic.SetCategory(categories)
	ic.SetStage("dev")
	ic.SetStatus("Success") //or get result status from scan
	ic.SetInteractionType("Scan done")
	summary := createTestSummary(&data, c)
	ic.SetTestSummary(summary)
	ic.SetType("Analytics")

	capturedCh := testutil.MockAndCaptureWorkflowInvocation(t, engineMock, localworkflows.WORKFLOWID_REPORT_ANALYTICS, 1)

	// Act
	f.ProcessResults(t.Context(), data)

	// Wait for async analytics sending
	captured := testsupport.RequireEventuallyReceive(t, capturedCh, time.Second, 10*time.Millisecond, "analytics should have been sent")

	// Assert: Verify analytics payload
	actualV2InstrumentationObject, err := analytics.GetV2InstrumentationObject(ic)
	require.NoError(t, err)
	assert.Equal(t, "snyk-ls", actualV2InstrumentationObject.Data.Attributes.Runtime.Application.Name)
	assert.Equal(t, "dev", string(*actualV2InstrumentationObject.Data.Attributes.Interaction.Stage))
	assert.Equal(t, "Success", actualV2InstrumentationObject.Data.Attributes.Interaction.Status)
	assert.Equal(t, "Scan done", actualV2InstrumentationObject.Data.Attributes.Interaction.Type)
	assert.Equal(t, []string{data.Product.ToProductCodename(), "test"}, *actualV2InstrumentationObject.Data.Attributes.Interaction.Categories)
	assert.Equal(t, "Analytics", actualV2InstrumentationObject.Data.Type)
	assert.Empty(t, actualV2InstrumentationObject.Data.Attributes.Interaction.Errors)
	assert.Equal(t, []map[string]any{{"name": "medium", "count": 1}}, *actualV2InstrumentationObject.Data.Attributes.Interaction.Results)

	// Assert: Verify analytics sent with correct folder org
	actualOrg := captured.Config.Get(configuration.ORGANIZATION)
	assert.Equal(t, testFolderOrg, actualOrg, "analytics should use folder-specific org")
}

func Test_processResults_ShouldReportScanSourceAndDeltaScanType(t *testing.T) {
	c := testutil.UnitTest(t)

	engineMock, gafConfig := testutil.SetUpEngineMock(t, c)

	notifier := notification.NewNotifier()
	f, _ := NewMockFolderWithScanNotifier(c, notifier)
	setupWorkspaceWithFolder(c, f, notifier)

	const testFolderOrg = "test-org"
	err := storedconfig.UpdateFolderConfig(gafConfig, &types.FolderConfig{
		FolderPath:                  f.path,
		PreferredOrg:                testFolderOrg,
		OrgSetByUser:                true,
		OrgMigratedFromGlobalConfig: true,
	}, c.Logger())
	require.NoError(t, err)

	scanData := types.ScanData{
		Product:           product.ProductOpenSource,
		Path:              f.path,
		UpdateGlobalCache: true,
		SendAnalytics:     true,
	}

	engineMock.EXPECT().GetWorkflows().AnyTimes()

	// Capture analytics WF's data and config (using channel for safe goroutine communication)
	capturedCh := testutil.MockAndCaptureWorkflowInvocation(t, engineMock, localworkflows.WORKFLOWID_REPORT_ANALYTICS, 1)

	ctx := context2.NewContextWithScanSource(context2.NewContextWithDeltaScanType(t.Context(), context2.WorkingDirectory), context2.LLM)

	// Act
	f.ProcessResults(ctx, scanData)

	// Wait for async analytics sending
	captured := testsupport.RequireEventuallyReceive(t, capturedCh, time.Second, 10*time.Millisecond, "analytics should have been sent")

	// Assert: Verify payload contains scan_source and scan_type
	require.Len(t, captured.Input, 1)
	payload := string(captured.Input[0].GetPayload().([]byte))
	require.NotEmpty(t, payload)
	assert.Contains(t, payload, "scan_source")
	assert.Contains(t, payload, "scan_type")

	// Assert: Verify analytics sent with correct folder org
	actualOrg := captured.Config.Get(configuration.ORGANIZATION)
	assert.Equal(t, testFolderOrg, actualOrg, "analytics should use folder-specific org")
}

func Test_processResults_ShouldCountSeverityByProduct(t *testing.T) {
	c := testutil.UnitTest(t)

	notifier := notification.NewNotifier()
	f, _ := NewMockFolderWithScanNotifier(c, notifier)

	engineMock, gafConfig := testutil.SetUpEngineMock(t, c)

	// Setup workspace with folder for analytics
	setupWorkspaceWithFolder(c, f, notifier)

	// Configure folder-specific org
	const testFolderOrg = "test-folder-org-uuid"
	folderConfig := &types.FolderConfig{
		FolderPath:                  f.Path(),
		PreferredOrg:                testFolderOrg,
		OrgSetByUser:                true,
		OrgMigratedFromGlobalConfig: true,
	}
	err := storedconfig.UpdateFolderConfig(gafConfig, folderConfig, c.Logger())
	require.NoError(t, err, "failed to configure folder org")

	filePath := types.FilePath(filepath.Join(string(f.Path()), "dummy.java"))
	scanData := types.ScanData{
		Product: product.ProductOpenSource,
		Path:    f.Path(),
		Issues: []types.Issue{
			&snyk.Issue{Severity: types.Critical, Product: product.ProductOpenSource, AffectedFilePath: filePath, AdditionalData: snyk.OssIssueData{Key: util.Result(uuid.NewUUID()).String()}},
			&snyk.Issue{Severity: types.Critical, Product: product.ProductOpenSource, AffectedFilePath: filePath, AdditionalData: snyk.OssIssueData{Key: util.Result(uuid.NewUUID()).String()}},
			&snyk.Issue{Severity: types.Critical, IsIgnored: true, Product: product.ProductOpenSource, AffectedFilePath: filePath, AdditionalData: snyk.OssIssueData{Key: util.Result(uuid.NewUUID()).String()}},
			&snyk.Issue{Severity: types.High, Product: product.ProductOpenSource, AffectedFilePath: filePath, AdditionalData: snyk.OssIssueData{Key: util.Result(uuid.NewUUID()).String()}},
			&snyk.Issue{Severity: types.High, Product: product.ProductOpenSource, AffectedFilePath: filePath, AdditionalData: snyk.OssIssueData{Key: util.Result(uuid.NewUUID()).String()}},
		},
		UpdateGlobalCache: true,
		SendAnalytics:     true,
	}

	engineMock.EXPECT().GetWorkflows().AnyTimes()

	// Capture analytics WF's data and config to verify folder org
	capturedCh := testutil.MockAndCaptureWorkflowInvocation(t, engineMock, localworkflows.WORKFLOWID_REPORT_ANALYTICS, 1)

	// Act
	f.ProcessResults(t.Context(), scanData)

	// Assert: Verify severity counts
	require.NotEmpty(t, scanData.GetSeverityIssueCounts())
	require.Equal(t, product.ProductOpenSource, scanData.Product)
	require.Equal(t, 3, scanData.GetSeverityIssueCounts()[types.Critical].Total)
	require.Equal(t, 2, scanData.GetSeverityIssueCounts()[types.Critical].Open)
	require.Equal(t, 1, scanData.GetSeverityIssueCounts()[types.Critical].Ignored)

	// Wait for async analytics sending and verify org
	captured := testsupport.RequireEventuallyReceive(t, capturedCh, time.Second, 10*time.Millisecond, "analytics should have been sent")
	actualOrg := captured.Config.Get(configuration.ORGANIZATION)
	assert.Equal(t, testFolderOrg, actualOrg, "analytics should use folder-specific org")
}

func Test_NewFolder_NormalizesPath(t *testing.T) {
	tests := []struct {
		name        string
		inputPath   types.FilePath
		expected    types.FilePath
		windowsOnly bool
	}{
		{
			name:      "removes trailing slash",
			inputPath: "/some/path/to/folder/",
			expected:  "/some/path/to/folder",
		},
		{
			name:        "removes trailing backslash (Windows)",
			inputPath:   `C:\Users\test\folder\`,
			expected:    `C:\Users\test\folder`,
			windowsOnly: true,
		},
		{
			name:      "cleans double separators",
			inputPath: "/some//path/to///folder",
			expected:  "/some/path/to/folder",
		},
		{
			name:      "consistent with PathKey",
			inputPath: "/some/path/to/folder/",
			expected:  types.PathKey("/some/path/to/folder/"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.windowsOnly {
				testsupport.OnlyOnWindows(t, "Windows-specific path normalization test")
			} else {
				testsupport.NotOnWindows(t, "Unix-specific path normalization test")
			}
			c := testutil.UnitTest(t)

			f := NewFolder(
				c,
				tt.inputPath,
				"test",
				scanner.NewTestScanner(),
				hover.NewFakeHoverService(),
				scanner.NewMockScanNotifier(),
				notification.NewMockNotifier(),
				persistence.NewNopScanPersister(),
				scanstates.NewNoopStateAggregator(),
				featureflag.NewFakeService(),
				nil,
			)

			assert.Equal(t, tt.expected, f.Path())
		})
	}
}

func Test_GetDelta_BaselineMissingVsSnapshotCorrupted(t *testing.T) {
	tests := []struct {
		name                string
		persistedListErr    error
		expectedReturnedErr error
	}{
		{
			name:                "baseline missing returns error",
			persistedListErr:    persistence.ErrBaselineDoesntExist,
			expectedReturnedErr: persistence.ErrBaselineDoesntExist,
		},
		{
			name:                "snapshot corrupted returns error",
			persistedListErr:    persistence.ErrSnapshotCorrupted,
			expectedReturnedErr: persistence.ErrSnapshotCorrupted,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testutil.UnitTest(t)
			ctrl := gomock.NewController(t)

			folderPath := types.FilePath(t.TempDir())
			filePath := types.FilePath(filepath.Join(string(folderPath), "test.go"))

			mockPersister := mock_persistence.NewMockScanSnapshotPersister(ctrl)
			mockPersister.EXPECT().
				GetPersistedIssueList(gomock.Any(), product.ProductCode).
				Return(nil, tt.persistedListErr).
				Times(1)

			sc := scanner.NewTestScanner()
			sc.Issues = []types.Issue{
				&snyk.Issue{
					ID:               "issue-1",
					AffectedFilePath: filePath,
					Severity:         types.High,
					Product:          product.ProductCode,
					AdditionalData:   snyk.CodeIssueData{Key: "key-1"},
				},
			}

			f := NewFolder(c, folderPath, "test", sc,
				hover.NewFakeHoverService(), scanner.NewMockScanNotifier(),
				notification.NewMockNotifier(), mockPersister,
				scanstates.NewNoopStateAggregator(), featureflag.NewFakeService(), nil)

			f.documentDiagnosticCache.Store(filePath, sc.Issues)

			result, err := f.GetDelta(product.ProductCode)

			assert.ErrorIs(t, err, tt.expectedReturnedErr)
			assert.Nil(t, result)
		})
	}
}

// setupWorkspaceWithFolder creates a workspace and adds the given folder to it
func setupWorkspaceWithFolder(c *config.Config, folder *Folder, notifier notification.Notifier) {
	w := New(c, performance.NewInstrumentor(), scanner.NewTestScanner(), hover.NewFakeHoverService(),
		scanner.NewMockScanNotifier(), notifier, persistence.NewNopScanPersister(),
		scanstates.NewNoopStateAggregator(), featureflag.NewFakeService(), nil)
	c.SetWorkspace(w)
	w.AddFolder(folder)
}

func NewMockFolder(c *config.Config, notifier notification.Notifier) *Folder {
	return NewFolder(c, "dummy", "dummy", scanner.NewTestScanner(), hover.NewFakeHoverService(), scanner.NewMockScanNotifier(), notifier, persistence.NewNopScanPersister(), scanstates.NewNoopStateAggregator(), featureflag.NewFakeService(), nil)
}

func NewMockFolderWithScanNotifier(c *config.Config, notifier notification.Notifier) (*Folder, *scanner.MockScanNotifier) {
	scanNotifier := scanner.NewMockScanNotifier()
	return NewFolder(c, "dummy", "dummy", scanner.NewTestScanner(), hover.NewFakeHoverService(), scanNotifier, notifier, persistence.NewNopScanPersister(), scanstates.NewNoopStateAggregator(), featureflag.NewFakeService(), nil), scanNotifier
}

func GetValueFromMap(m *xsync.MapOf[types.FilePath, []types.Issue], key types.FilePath) []types.Issue {
	value, _ := m.Load(key)
	return value
}
