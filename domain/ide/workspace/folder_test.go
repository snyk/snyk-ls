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
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	context2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/testsupport"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/puzpuzpuz/xsync/v3"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/internal/types"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/internal/notification"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/util"
)

func Test_Scan_WhenNoIssues_shouldNotProcessResults(t *testing.T) {
	hoverRecorder := hover.NewFakeHoverService()
	c := testutil.UnitTest(t)
	f := NewFolder(c, "dummy", "dummy", scanner.NewTestScanner(), hoverRecorder, scanner.NewMockScanNotifier(), notification.NewMockNotifier(), persistence.NewNopScanPersister(), scanstates.NewNoopStateAggregator())

	data := types.ScanData{
		Product:           "",
		Issues:            []types.Issue{},
		UpdateGlobalCache: true,
		SendAnalytics:     true,
	}
	f.ProcessResults(context.Background(), data)

	assert.Equal(t, 0, hoverRecorder.Calls())
}

func Test_ProcessResults_whenDifferentPaths_AddsToCache(t *testing.T) {
	c := testutil.UnitTest(t)
	f := NewFolder(c, "dummy", "dummy", scanner.NewTestScanner(), hover.NewFakeHoverService(), scanner.NewMockScanNotifier(), notification.NewMockNotifier(), persistence.NewNopScanPersister(), scanstates.NewNoopStateAggregator())

	path1 := types.FilePath(filepath.Join(string(f.path), "path1"))
	path2 := types.FilePath(filepath.Join(string(f.path), "path2"))
	data := types.ScanData{
		Product: product.ProductOpenSource,
		Issues: []types.Issue{
			NewMockIssue("id1", path1),
			NewMockIssue("id2", path2),
		},
		UpdateGlobalCache: true,
		SendAnalytics:     true,
	}
	f.ScanFolder(context.Background())
	f.ProcessResults(context.Background(), data)

	assert.Equal(t, 2, f.documentDiagnosticCache.Size())
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, path1))
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, path2))
	assert.Len(t, GetValueFromMap(f.documentDiagnosticCache, path1), 1)
	assert.Len(t, GetValueFromMap(f.documentDiagnosticCache, path2), 1)
}

func Test_ProcessResults_whenSamePaths_AddsToCache(t *testing.T) {
	c := testutil.UnitTest(t)
	f := NewFolder(c, "dummy", "dummy", scanner.NewTestScanner(), hover.NewFakeHoverService(), scanner.NewMockScanNotifier(), notification.NewMockNotifier(), persistence.NewNopScanPersister(), scanstates.NewNoopStateAggregator())

	filePath := types.FilePath("dummy/path1")
	data := types.ScanData{
		Product: product.ProductOpenSource,
		Issues: []types.Issue{
			NewMockIssue("id1", filePath),
			NewMockIssue("id2", filePath),
		},
		UpdateGlobalCache: true,
		SendAnalytics:     true,
	}
	f.ProcessResults(context.Background(), data)

	assert.Equal(t, 1, len(f.Issues()))
	assert.Len(t, f.IssuesForFile(filePath), 2)
}

func Test_ProcessResults_whenDifferentPaths_AccumulatesIssues(t *testing.T) {
	c := testutil.UnitTest(t)
	f := NewMockFolder(c, notification.NewMockNotifier())

	path1 := types.FilePath(filepath.Join(string(f.path), "path1"))
	path2 := types.FilePath(filepath.Join(string(f.path), "path2"))
	path3 := types.FilePath(filepath.Join(string(f.path), "path3"))
	data := types.ScanData{
		Product: product.ProductOpenSource,
		Issues: []types.Issue{
			NewMockIssue("id1", path1),
			NewMockIssue("id2", path2),
			NewMockIssue("id3", path3),
		},
		UpdateGlobalCache: true,
		SendAnalytics:     true,
	}
	f.ProcessResults(context.Background(), data)

	assert.Len(t, f.Issues(), 3)
	assert.Len(t, f.IssuesForFile(path1), 1)
	assert.Len(t, f.IssuesForFile(path2), 1)
	assert.Len(t, f.IssuesForFile(path3), 1)
}

func Test_ProcessResults_whenSamePaths_AccumulatesIssues(t *testing.T) {
	c := testutil.UnitTest(t)
	f := NewMockFolder(c, notification.NewMockNotifier())

	path1 := types.FilePath(filepath.Join(string(f.path), "path1"))
	data := types.ScanData{
		Product: product.ProductOpenSource,
		Issues: []types.Issue{
			NewMockIssue("id1", path1),
			NewMockIssue("id2", path1),
			NewMockIssue("id3", path1),
		},
		UpdateGlobalCache: true,
		SendAnalytics:     true,
	}
	f.ProcessResults(context.Background(), data)

	assert.Len(t, f.Issues(), 1)
	issuesForFile := f.IssuesForFile(path1)
	assert.NotNil(t, issuesForFile)
	assert.Len(t, issuesForFile, 3)
}

func Test_ProcessResults_whenSamePathsAndDuplicateIssues_DeDuplicates(t *testing.T) {
	c := testutil.UnitTest(t)
	f := NewMockFolder(c, notification.NewMockNotifier())

	path1 := types.FilePath(filepath.Join(string(f.path), "path1"))
	path2 := types.FilePath(filepath.Join(string(f.path), "path2"))
	issue1 := NewMockIssue("id1", path1)
	issue2 := NewMockIssue("id2", path1)
	issue3 := NewMockIssue("id3", path1)
	issue4 := NewMockIssue("id1", path2)
	issue5 := NewMockIssue("id3", path2)

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
	f.ProcessResults(context.Background(), data)

	assert.Len(t, f.Issues(), 2)
	issuesForFile := f.IssuesForFile(path1)
	assert.NotNil(t, issuesForFile)
	assert.Len(t, issuesForFile, 3)
}

func TestProcessResults_whenFilteringSeverity_ProcessesOnlyFilteredIssues(t *testing.T) {
	c := testutil.UnitTest(t)

	severityFilter := types.NewSeverityFilter(true, false, true, false)
	config.CurrentConfig().SetSeverityFilter(&severityFilter)

	f := NewMockFolder(c, notification.NewNotifier())

	path1 := types.FilePath(filepath.Join(string(f.path), "path1"))
	data := types.ScanData{
		Product: product.ProductOpenSource,
		Issues: []types.Issue{
			NewMockIssueWithSeverity("id1", types.FilePath(filepath.Join(string(f.path), string(path1))), types.Critical),
			NewMockIssueWithSeverity("id2", types.FilePath(filepath.Join(string(f.path), string(path1))), types.High),
			NewMockIssueWithSeverity("id3", types.FilePath(filepath.Join(string(f.path), string(path1))), types.Medium),
			NewMockIssueWithSeverity("id4", types.FilePath(filepath.Join(string(f.path), string(path1))), types.Low),
			NewMockIssueWithSeverity("id5", types.FilePath(filepath.Join(string(f.path), string(path1))), types.Critical),
		},
		UpdateGlobalCache: true,
		SendAnalytics:     true,
	}
	f.ProcessResults(context.Background(), data)

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
	config.CurrentConfig().SetIssueViewOptions(&issueViewOptions)

	f := NewMockFolder(c, notification.NewNotifier())

	path1 := types.FilePath(filepath.Join(string(f.path), "path1"))
	data := types.ScanData{
		Product: product.ProductOpenSource,
		Issues: []types.Issue{
			NewMockIssueWithIgnored("id1", types.FilePath(filepath.Join(string(f.path), string(path1))), true),
			NewMockIssueWithIgnored("id2", types.FilePath(filepath.Join(string(f.path), string(path1))), false),
			NewMockIssueWithIgnored("id3", types.FilePath(filepath.Join(string(f.path), string(path1))), true),
			NewMockIssueWithIgnored("id4", types.FilePath(filepath.Join(string(f.path), string(path1))), false),
			NewMockIssueWithIgnored("id5", types.FilePath(filepath.Join(string(f.path), string(path1))), true),
		},
		UpdateGlobalCache: true,
		SendAnalytics:     false,
	}

	ctrl := gomock.NewController(t)
	mockConfiguration := mocks.NewMockConfiguration(ctrl)
	config.CurrentConfig().Engine().SetConfiguration(mockConfiguration)
	mockConfiguration.EXPECT().GetBool(configuration.FF_CODE_CONSISTENT_IGNORES).Return(true)

	f.ProcessResults(context.Background(), data)

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
	f := NewMockFolder(c, notification.NewNotifier())

	path1 := types.FilePath(filepath.Join(string(f.path), "path1"))
	path2 := types.FilePath(filepath.Join(string(f.path), "path2"))
	data := types.ScanData{
		Product: product.ProductOpenSource,
		Issues: []types.Issue{
			NewMockIssue("id1", path1),
			NewMockIssue("id2", path2),
		},
		UpdateGlobalCache: true,
		SendAnalytics:     true,
	}
	f.ProcessResults(context.Background(), data)
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
	config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)
	f := NewFolder(c, "dummy", "dummy", scanner.NewTestScanner(), hover.NewFakeHoverService(), scanner.NewMockScanNotifier(), notification.NewMockNotifier(), persistence.NewNopScanPersister(), scanstates.NewNoopStateAggregator())
	assert.False(t, f.IsTrusted())
}

func Test_IsTrusted_shouldReturnTrueForPathContainedInTrustedFolders(t *testing.T) {
	c := testutil.UnitTest(t)
	config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)
	config.CurrentConfig().SetTrustedFolders([]types.FilePath{"dummy"})
	f := NewFolder(c, "dummy", "dummy", scanner.NewTestScanner(), hover.NewFakeHoverService(), scanner.NewMockScanNotifier(), notification.NewMockNotifier(), persistence.NewNopScanPersister(), scanstates.NewNoopStateAggregator())
	assert.True(t, f.IsTrusted())
}

func Test_IsTrusted_shouldReturnTrueForSubfolderOfTrustedFolders_Linux(t *testing.T) {
	c := testutil.IntegTest(t)
	testsupport.NotOnWindows(t, "Unix/macOS file paths are incompatible with Windows")
	config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)
	config.CurrentConfig().SetTrustedFolders([]types.FilePath{"/dummy"})
	f := NewFolder(c, "/dummy/dummyF", "dummy", scanner.NewTestScanner(), hover.NewFakeHoverService(), scanner.NewMockScanNotifier(), notification.NewMockNotifier(), persistence.NewNopScanPersister(), scanstates.NewNoopStateAggregator())
	assert.True(t, f.IsTrusted())
}

func Test_IsTrusted_shouldReturnFalseForDifferentFolder(t *testing.T) {
	c := testutil.UnitTest(t)
	config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)
	config.CurrentConfig().SetTrustedFolders([]types.FilePath{"/dummy"})
	f := NewFolder(c, "/UntrustedPath", "dummy", scanner.NewTestScanner(), hover.NewFakeHoverService(), scanner.NewMockScanNotifier(), notification.NewMockNotifier(), persistence.NewNopScanPersister(), scanstates.NewNoopStateAggregator())
	assert.False(t, f.IsTrusted())
}

func Test_IsTrusted_shouldReturnTrueForSubfolderOfTrustedFolders(t *testing.T) {
	c := testutil.IntegTest(t)
	testsupport.OnlyOnWindows(t, "Windows specific test")
	config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)
	config.CurrentConfig().SetTrustedFolders([]types.FilePath{"c:\\dummy"})
	f := NewFolder(c, "c:\\dummy\\dummyF", "dummy", scanner.NewTestScanner(), hover.NewFakeHoverService(), scanner.NewMockScanNotifier(), notification.NewMockNotifier(), persistence.NewNopScanPersister(), scanstates.NewNoopStateAggregator())
	assert.True(t, f.IsTrusted())
}

func Test_IsTrusted_shouldReturnTrueIfTrustFeatureDisabled(t *testing.T) {
	c := testutil.UnitTest(t) // disables trust feature
	f := NewFolder(c, "c:\\dummy\\dummyF", "dummy", scanner.NewTestScanner(), hover.NewFakeHoverService(), scanner.NewMockScanNotifier(), notification.NewMockNotifier(), persistence.NewNopScanPersister(), scanstates.NewNoopStateAggregator())
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

	f := NewFolder(c, folderPath, "Test", scannerRecorder, hover.NewFakeHoverService(), scanner.NewMockScanNotifier(), notification.NewMockNotifier(), persistence.NewNopScanPersister(), scanstates.NewNoopStateAggregator())
	ctx := context.Background()

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

	f := NewFolder(c, folderPath, "Test", scannerRecorder, hover.NewFakeHoverService(), scanner.NewMockScanNotifier(), notification.NewMockNotifier(), persistence.NewNopScanPersister(), scanstates.NewNoopStateAggregator())
	ctx := context.Background()

	ctrl := gomock.NewController(t)
	mockConfiguration := mocks.NewMockConfiguration(ctrl)
	c.Engine().SetConfiguration(mockConfiguration)
	mockConfiguration.EXPECT().GetBool(configuration.FF_CODE_CONSISTENT_IGNORES).Return(true).Times(2) // twice, since we filter in the scan then again to check, since we're too lazy to mock.

	c.SetIssueViewOptions(util.Ptr(types.NewIssueViewOptions(true, false)))

	// act
	f.ScanFile(ctx, filePath)
	filteredDiagnostics := f.filterDiagnostics(f.Issues())

	// assert
	assert.Len(t, filteredDiagnostics[filePath], 2)
	assert.Contains(t, filteredDiagnostics[filePath], openIssue1)
	assert.Contains(t, filteredDiagnostics[filePath], openIssue2)
}

func Test_ClearDiagnosticsByIssueType(t *testing.T) {
	// Arrange
	c := testutil.UnitTest(t)
	f := NewMockFolder(c, notification.NewMockNotifier())
	filePath := types.FilePath(filepath.Join(string(f.path), "path1"))
	mockOpenSourceIssue := NewMockIssue("id1", filePath)
	removedIssueType := product.FilterableIssueTypeOpenSource
	mockOpenSourceIssue.Product = product.ProductOpenSource
	mockIacIssue := NewMockIssue("id2", filePath)
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
	f.ProcessResults(context.Background(), data)
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

	f, scanNotifier := NewMockFolderWithScanNotifier(c, notification.NewMockNotifier())
	var path = "path1"
	mockCodeIssue := NewMockIssue("id1", types.FilePath(filepath.Join(string(f.path), path)))

	data := types.ScanData{
		Product:           product.ProductOpenSource,
		Issues:            []types.Issue{mockCodeIssue},
		UpdateGlobalCache: true,
		SendAnalytics:     true,
	}
	// Act
	f.ProcessResults(context.Background(), data)

	// Assert
	assert.Len(t, scanNotifier.SuccessCalls(), 1)
}

func Test_processResults_ShouldSendError(t *testing.T) {
	// Arrange
	c := testutil.UnitTest(t)

	f, scanNotifier := NewMockFolderWithScanNotifier(c, notification.NewMockNotifier())
	const filePath = "path1"
	mockCodeIssue := NewMockIssue("id1", filePath)

	data := types.ScanData{
		Product: product.ProductOpenSource,
		Issues: []types.Issue{
			mockCodeIssue,
		},
		UpdateGlobalCache: true,
		SendAnalytics:     true,
		Err:               errors.New("test error"),
	} // Act
	f.ProcessResults(context.Background(), data)

	// Assert
	assert.Empty(t, scanNotifier.SuccessCalls())
	assert.Len(t, scanNotifier.ErrorCalls(), 1)
}

func Test_processResults_ShouldSendAnalyticsToAPI(t *testing.T) {
	c := testutil.UnitTest(t)

	gafConfig := configuration.NewWithOpts(
		configuration.WithAutomaticEnv(),
	)
	engineMock := workflow.NewWorkFlowEngine(gafConfig)
	c.SetEngine(engineMock)

	f, _ := NewMockFolderWithScanNotifier(c, notification.NewNotifier())
	filePath := types.FilePath(filepath.Join(string(f.path), "path1"))
	mockCodeIssue := NewMockIssue("id1", filePath)

	data := types.ScanData{
		Product:           product.ProductOpenSource,
		Issues:            []types.Issue{mockCodeIssue},
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

	entered := make(chan struct{})
	_, err := engineMock.Register(localworkflows.WORKFLOWID_REPORT_ANALYTICS, workflow.ConfigurationOptionsFromFlagset(pflag.NewFlagSet("", pflag.ContinueOnError)),
		func(invocation workflow.InvocationContext, workflowInputData []workflow.Data) ([]workflow.Data, error) {
			actualV2InstrumentationObject, err := analytics.GetV2InstrumentationObject(ic)

			require.NoError(t, err)

			require.Equal(t, "snyk-ls", actualV2InstrumentationObject.Data.Attributes.Runtime.Application.Name)
			require.Equal(t, "dev", string(*actualV2InstrumentationObject.Data.Attributes.Interaction.Stage))
			require.Equal(t, "Success", actualV2InstrumentationObject.Data.Attributes.Interaction.Status)
			require.Equal(t, "Scan done", actualV2InstrumentationObject.Data.Attributes.Interaction.Type)
			require.Equal(t, []string{data.Product.ToProductCodename(), "test"}, *actualV2InstrumentationObject.Data.Attributes.Interaction.Categories)
			require.Equal(t, "Analytics", actualV2InstrumentationObject.Data.Type)
			require.Empty(t, actualV2InstrumentationObject.Data.Attributes.Interaction.Errors)
			require.Equal(t, []map[string]interface{}{{"name": "medium", "count": 1}}, *actualV2InstrumentationObject.Data.Attributes.Interaction.Results)

			close(entered)
			return nil, nil
		})

	assert.NoError(t, err)

	err = engineMock.Init()
	assert.NoError(t, err)

	// Act
	f.ProcessResults(context.Background(), data)
	maxWaitTime := 10 * time.Second

	select {
	case <-entered:
	case <-time.After(maxWaitTime):
		t.Fatalf("time out. condition wasn't met. current timeout value is: %s", maxWaitTime)
	}
}

func Test_processResults_ShouldReportScanSourceAndDeltaScanType(t *testing.T) {
	c := testutil.UnitTest(t)

	engineMock, gafConfig := setUpEngineMock(t, c)

	f, _ := NewMockFolderWithScanNotifier(c, notification.NewNotifier())

	scanData := types.ScanData{
		Product:           product.ProductOpenSource,
		UpdateGlobalCache: true,
		SendAnalytics:     true,
	}

	engineMock.EXPECT().GetConfiguration().AnyTimes().Return(gafConfig)
	engineMock.EXPECT().GetWorkflows().AnyTimes()
	engineMock.EXPECT().InvokeWithInputAndConfig(localworkflows.WORKFLOWID_REPORT_ANALYTICS, gomock.Any(), gomock.Any()).
		Times(1).
		Do(func(id workflow.Identifier, data []workflow.Data, config configuration.Configuration) {
			require.Len(t, data, 1)
			payload := string(data[0].GetPayload().([]byte))
			require.NotEmpty(t, payload)
			require.Contains(t, payload, "scan_source")
			require.Contains(t, payload, "scan_type")
		})

	ctx := context2.NewContextWithScanSource(context2.NewContextWithDeltaScanType(context.Background(), context2.WorkingDirectory), context2.LLM)

	// Act
	f.ProcessResults(ctx, scanData)
	time.Sleep(time.Second)
}

func Test_processResults_ShouldCountSeverityByProduct(t *testing.T) {
	c := testutil.UnitTest(t)

	engineMock, gafConfig := setUpEngineMock(t, c)

	f, _ := NewMockFolderWithScanNotifier(c, notification.NewNotifier())

	filePath := types.FilePath(filepath.Join(string(f.Path()), "dummy.java"))
	scanData := types.ScanData{
		Product: product.ProductOpenSource,
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

	engineMock.EXPECT().GetConfiguration().AnyTimes().Return(gafConfig)
	engineMock.EXPECT().GetWorkflows().AnyTimes()
	engineMock.EXPECT().InvokeWithInputAndConfig(localworkflows.WORKFLOWID_REPORT_ANALYTICS, gomock.Any(), gomock.Any()).
		Times(1)

	// Act
	f.ProcessResults(context.Background(), scanData)

	// Assert
	require.NotEmpty(t, scanData.GetSeverityIssueCounts())
	require.Equal(t, product.ProductOpenSource, scanData.Product)
	require.Equal(t, 3, scanData.GetSeverityIssueCounts()[types.Critical].Total)
	require.Equal(t, 2, scanData.GetSeverityIssueCounts()[types.Critical].Open)
	require.Equal(t, 1, scanData.GetSeverityIssueCounts()[types.Critical].Ignored)

	// wait for async analytics sending
	time.Sleep(time.Second)
}

func NewMockFolder(c *config.Config, notifier noti.Notifier) *Folder {
	return NewFolder(c, "dummy", "dummy", scanner.NewTestScanner(), hover.NewFakeHoverService(), scanner.NewMockScanNotifier(), notifier, persistence.NewNopScanPersister(), scanstates.NewNoopStateAggregator())
}

func NewMockFolderWithScanNotifier(c *config.Config, notifier noti.Notifier) (*Folder, *scanner.MockScanNotifier) {
	scanNotifier := scanner.NewMockScanNotifier()
	return NewFolder(c, "dummy", "dummy", scanner.NewTestScanner(), hover.NewFakeHoverService(), scanNotifier, notifier, persistence.NewNopScanPersister(), scanstates.NewNoopStateAggregator()), scanNotifier
}

func NewMockIssue(id string, path types.FilePath) *snyk.Issue {
	return &snyk.Issue{
		ID:               id,
		AffectedFilePath: path,
		Product:          product.ProductOpenSource,
		Severity:         types.Medium,
		AdditionalData:   snyk.OssIssueData{Key: util.Result(uuid.NewUUID()).String()},
	}
}

func NewMockIssueWithSeverity(id string, path types.FilePath, severity types.Severity) *snyk.Issue {
	issue := NewMockIssue(id, path)
	issue.Severity = severity

	return issue
}

func NewMockIssueWithIgnored(id string, path types.FilePath, ignored bool) *snyk.Issue {
	issue := NewMockIssue(id, path)
	issue.IsIgnored = ignored

	return issue
}

func GetValueFromMap(m *xsync.MapOf[types.FilePath, []types.Issue], key types.FilePath) []types.Issue {
	value, _ := m.Load(key)
	return value
}

func setUpEngineMock(t *testing.T, c *config.Config) (*mocks.MockEngine, configuration.Configuration) {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockEngine := mocks.NewMockEngine(ctrl)
	engineConfig := c.Engine().GetConfiguration()
	c.SetEngine(mockEngine)
	return mockEngine, engineConfig
}
