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
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/puzpuzpuz/xsync/v3"
	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	noti "github.com/snyk/snyk-ls/domain/ide/notification"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/lsp"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_Scan_WhenCachedResults_shouldNotReScan(t *testing.T) {
	testutil.UnitTest(t)
	folderPath, filePath := "testFolderDir", "testPath"
	scanner := snyk.NewTestScanner()

	scanner.Issues = []snyk.Issue{NewMockIssue("1", filePath)}
	f := NewFolder(folderPath, "Test", scanner, hover.NewFakeHoverService(), snyk.NewMockScanNotifier(), notification.NewNotifier())
	ctx := context.Background()

	f.ScanFile(ctx, filePath)
	f.ScanFile(ctx, filePath)

	assert.Equal(t, 1, scanner.Calls())
}

func Test_Scan_WhenNoIssues_shouldNotProcessResults(t *testing.T) {
	hoverRecorder := hover.NewFakeHoverService()
	testutil.UnitTest(t)
	f := NewFolder("dummy", "dummy", snyk.NewTestScanner(), hoverRecorder, snyk.NewMockScanNotifier(), notification.NewNotifier())

	data := snyk.ScanData{
		Product: "",
		Issues:  []snyk.Issue{},
	}
	f.processResults(data)

	assert.Equal(t, 0, hoverRecorder.Calls())
}

func TestProcessResults_SendsDiagnosticsAndHovers(t *testing.T) {
	t.Skipf("test this once we have uniform abstractions for hover & diagnostics")
	testutil.UnitTest(t)
	hoverService := hover.NewFakeHoverService()
	f := NewFolder("dummy", "dummy", snyk.NewTestScanner(), hoverService, snyk.NewMockScanNotifier(), notification.NewNotifier())

	issues := []snyk.Issue{
		NewMockIssue("id1", "path1"),
		NewMockIssue("id2", "path2"),
	}

	data := snyk.ScanData{
		Product: product.ProductOpenSource,
		Issues:  issues,
	}

	f.processResults(data)
	// todo ideally there's a hover & diagnostic service that are symmetric and don't leak implementation details (e.g. channels)
	// assert.hoverService.GetAll()
}

func Test_ProcessResults_whenDifferentPaths_AddsToCache(t *testing.T) {
	testutil.UnitTest(t)
	f := NewFolder("dummy", "dummy", snyk.NewTestScanner(), hover.NewFakeHoverService(), snyk.NewMockScanNotifier(), notification.NewNotifier())

	data := snyk.ScanData{
		Product: product.ProductOpenSource,
		Issues: []snyk.Issue{
			NewMockIssue("id1", "path1"),
			NewMockIssue("id2", "path2"),
		},
	}
	f.processResults(data)

	assert.Equal(t, 2, f.documentDiagnosticCache.Size())
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, "path1"))
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, "path2"))
	assert.Len(t, GetValueFromMap(f.documentDiagnosticCache, "path1"), 1)
	assert.Len(t, GetValueFromMap(f.documentDiagnosticCache, "path2"), 1)
}

func Test_ProcessResults_whenSamePaths_AddsToCache(t *testing.T) {
	testutil.UnitTest(t)
	f := NewFolder("dummy", "dummy", snyk.NewTestScanner(), hover.NewFakeHoverService(), snyk.NewMockScanNotifier(), notification.NewNotifier())

	data := snyk.ScanData{
		Product: product.ProductOpenSource,
		Issues: []snyk.Issue{
			NewMockIssue("id1", "path1"),
			NewMockIssue("id2", "path1"),
		},
	}
	f.processResults(data)

	assert.Equal(t, 1, f.documentDiagnosticCache.Size())
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, "path1"))
	assert.Len(t, GetValueFromMap(f.documentDiagnosticCache, "path1"), 2)
}

func Test_ProcessResults_whenDifferentPaths_AccumulatesIssues(t *testing.T) {
	testutil.UnitTest(t)
	f := NewMockFolder(notification.NewNotifier())

	data := snyk.ScanData{
		Product: product.ProductOpenSource,
		Issues: []snyk.Issue{
			NewMockIssue("id1", "path1"),
			NewMockIssue("id2", "path2"),
		},
	}
	f.processResults(data)

	data.Issues = []snyk.Issue{NewMockIssue("id3", "path3")}
	f.processResults(data)

	assert.Equal(t, 3, f.documentDiagnosticCache.Size())
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, "path1"))
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, "path2"))
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, "path3"))
}

func Test_ProcessResults_whenSamePaths_AccumulatesIssues(t *testing.T) {
	testutil.UnitTest(t)
	f := NewMockFolder(notification.NewNotifier())

	data := snyk.ScanData{
		Product: product.ProductOpenSource,
		Issues: []snyk.Issue{
			NewMockIssue("id1", "path1"),
			NewMockIssue("id2", "path1"),
		},
	}
	f.processResults(data)

	data.Issues = []snyk.Issue{NewMockIssue("id3", "path1")}
	f.processResults(data)

	assert.Equal(t, 1, f.documentDiagnosticCache.Size())
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, "path1"))
	assert.Len(t, GetValueFromMap(f.documentDiagnosticCache, "path1"), 3)
}

func Test_ProcessResults_whenSamePathsAndDuplicateIssues_DeDuplicates(t *testing.T) {
	testutil.UnitTest(t)
	f := NewMockFolder(notification.NewNotifier())

	data := snyk.ScanData{
		Product: product.ProductOpenSource,
		Issues: []snyk.Issue{
			NewMockIssue("id1", "path1"),
			NewMockIssue("id2", "path1"),
		},
	}
	f.processResults(data)

	data.Issues = []snyk.Issue{
		NewMockIssue("id1", "path1"),
		NewMockIssue("id3", "path1"),
	}
	f.processResults(data)

	data.Issues = []snyk.Issue{
		NewMockIssue("id1", ""),
		NewMockIssue("id3", ""),
	}
	f.processResults(data)

	assert.Equal(t, 2, f.documentDiagnosticCache.Size())
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, "path1"))
	assert.Len(t, GetValueFromMap(f.documentDiagnosticCache, "path1"), 3)
}

func TestProcessResults_whenFilteringSeverity_ProcessesOnlyFilteredIssues(t *testing.T) {
	testutil.UnitTest(t)
	c := config.New()
	config.SetCurrentConfig(c)

	severityFilter := lsp.NewSeverityFilter(true, false, true, false)
	config.CurrentConfig().SetSeverityFilter(severityFilter)

	f := NewMockFolder(notification.NewNotifier())

	data := snyk.ScanData{
		Product: product.ProductOpenSource,
		Issues: []snyk.Issue{
			NewMockIssueWithSeverity("id1", "path1", snyk.Critical),
			NewMockIssueWithSeverity("id2", "path1", snyk.High),
			NewMockIssueWithSeverity("id3", "path1", snyk.Medium),
			NewMockIssueWithSeverity("id4", "path1", snyk.Low),
			NewMockIssueWithSeverity("id5", "path1", snyk.Critical),
		},
	}
	f.processResults(data)

	mtx := &sync.Mutex{}
	var diagnostics []lsp.Diagnostic

	f.notifier.CreateListener(func(event any) {
		switch params := event.(type) {
		case lsp.PublishDiagnosticsParams:
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

			hasCorrectIssues := diagnostics[0].Code == "id1" && diagnostics[1].Code == "id3" && diagnostics[2].Code == "id5"
			return hasCorrectIssues
		},
		1*time.Second,
		10*time.Millisecond,
		"Expected to receive only critical issues",
	)
}

func Test_ClearDiagnostics(t *testing.T) {
	testutil.UnitTest(t)
	f := NewMockFolder(notification.NewNotifier())

	data := snyk.ScanData{
		Product: product.ProductOpenSource,
		Issues: []snyk.Issue{
			NewMockIssue("id1", "path1"),
			NewMockIssue("id2", "path2"),
		},
	}
	f.processResults(data)
	mtx := &sync.Mutex{}
	clearDiagnosticNotifications := 0

	f.notifier.DisposeListener()
	f.notifier.CreateListener(func(event any) {
		switch params := event.(type) {
		case lsp.PublishDiagnosticsParams:
			if len(params.Diagnostics) == 0 {
				mtx.Lock()
				clearDiagnosticNotifications++
				mtx.Unlock()
			}
		}
	})

	f.ClearDiagnostics()

	assert.Equal(t, 0, f.documentDiagnosticCache.Size())
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
	testutil.UnitTest(t)
	config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)
	f := NewFolder("dummy", "dummy", snyk.NewTestScanner(), hover.NewFakeHoverService(), snyk.NewMockScanNotifier(), notification.NewNotifier())
	assert.False(t, f.IsTrusted())
}

func Test_IsTrusted_shouldReturnTrueForPathContainedInTrustedFolders(t *testing.T) {
	testutil.UnitTest(t)
	config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)
	config.CurrentConfig().SetTrustedFolders([]string{"dummy"})
	f := NewFolder("dummy", "dummy", snyk.NewTestScanner(), hover.NewFakeHoverService(), snyk.NewMockScanNotifier(), notification.NewNotifier())
	assert.True(t, f.IsTrusted())
}

func Test_IsTrusted_shouldReturnTrueForSubfolderOfTrustedFolders_Linux(t *testing.T) {
	testutil.IntegTest(t)
	testutil.NotOnWindows(t, "Unix/macOS file paths are incompatible with Windows")
	config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)
	config.CurrentConfig().SetTrustedFolders([]string{"/dummy"})
	f := NewFolder("/dummy/dummyF", "dummy", snyk.NewTestScanner(), hover.NewFakeHoverService(), snyk.NewMockScanNotifier(), notification.NewNotifier())
	assert.True(t, f.IsTrusted())
}

func Test_IsTrusted_shouldReturnFalseForDifferentFolder(t *testing.T) {
	testutil.UnitTest(t)
	config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)
	config.CurrentConfig().SetTrustedFolders([]string{"/dummy"})
	f := NewFolder("/UntrustedPath", "dummy", snyk.NewTestScanner(), hover.NewFakeHoverService(), snyk.NewMockScanNotifier(), notification.NewNotifier())
	assert.False(t, f.IsTrusted())
}

func Test_IsTrusted_shouldReturnTrueForSubfolderOfTrustedFolders(t *testing.T) {
	testutil.IntegTest(t)
	testutil.OnlyOnWindows(t, "Windows specific test")
	config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)
	config.CurrentConfig().SetTrustedFolders([]string{"c:\\dummy"})
	f := NewFolder("c:\\dummy\\dummyF", "dummy", snyk.NewTestScanner(), hover.NewFakeHoverService(), snyk.NewMockScanNotifier(), notification.NewNotifier())
	assert.True(t, f.IsTrusted())
}

func Test_IsTrusted_shouldReturnTrueIfTrustFeatureDisabled(t *testing.T) {
	testutil.UnitTest(t) // disables trust feature
	f := NewFolder("c:\\dummy\\dummyF", "dummy", snyk.NewTestScanner(), hover.NewFakeHoverService(), snyk.NewMockScanNotifier(), notification.NewNotifier())
	assert.True(t, f.IsTrusted())
}

func Test_FilterCachedDiagnostics_filtersDisabledSeverity(t *testing.T) {
	testutil.UnitTest(t)

	// arrange
	filePath, folderPath := "test/path", "test"
	criticalIssue := snyk.Issue{AffectedFilePath: filePath, Severity: snyk.Critical, Product: product.ProductOpenSource}
	highIssue := snyk.Issue{AffectedFilePath: filePath, Severity: snyk.High, Product: product.ProductOpenSource}
	mediumIssue := snyk.Issue{AffectedFilePath: filePath, Severity: snyk.Medium, Product: product.ProductOpenSource}
	lowIssue := snyk.Issue{AffectedFilePath: filePath, Severity: snyk.Low, Product: product.ProductOpenSource}
	scannerRecorder := snyk.NewTestScanner()
	scannerRecorder.Issues = []snyk.Issue{
		criticalIssue,
		highIssue,
		mediumIssue,
		lowIssue,
	}

	f := NewFolder(folderPath, "Test", scannerRecorder, hover.NewFakeHoverService(), snyk.NewMockScanNotifier(), notification.NewNotifier())
	ctx := context.Background()

	config.CurrentConfig().SetSeverityFilter(lsp.NewSeverityFilter(true, true, false, false))

	// act
	f.ScanFile(ctx, filePath)
	filteredDiagnostics := f.filterCachedDiagnostics()

	// assert
	assert.Len(t, filteredDiagnostics[filePath], 2)
	assert.Contains(t, filteredDiagnostics[filePath], criticalIssue)
	assert.Contains(t, filteredDiagnostics[filePath], highIssue)
}

func Test_ClearDiagnosticsByIssueType(t *testing.T) {
	// Arrange
	testutil.UnitTest(t)
	f := NewMockFolder(notification.NewNotifier())
	const filePath = "path1"
	mockCodeIssue := NewMockIssue("id1", filePath)
	removedIssueType := product.FilterableIssueTypeOpenSource
	mockCodeIssue.Product = product.ProductOpenSource
	mockIacIssue := NewMockIssue("id2", filePath)
	mockIacIssue.Product = product.ProductInfrastructureAsCode
	data := snyk.ScanData{
		Product: product.ProductOpenSource,
		Issues: []snyk.Issue{
			mockIacIssue,
			mockCodeIssue,
		},
	}
	f.processResults(data)
	const expectedIssuesCountAfterRemoval = 1

	// Act
	f.ClearDiagnosticsByIssueType(removedIssueType)

	// Assert
	issues := f.AllIssuesFor(filePath)
	t.Run("Does not return diagnostics of that type", func(t *testing.T) {
		for _, issue := range issues {
			assert.NotEqual(t, removedIssueType, issue.Product)
		}
	})

	t.Run("Return diagnostics of other types", func(t *testing.T) {
		assert.Len(t, issues, expectedIssuesCountAfterRemoval)
	})
}

func Test_processResults_ShouldSendSuccess(t *testing.T) {
	// Arrange
	testutil.UnitTest(t)

	f, scanNotifier := NewMockFolderWithScanNotifier(notification.NewNotifier())
	const filePath = "path1"
	mockCodeIssue := NewMockIssue("id1", filePath)

	data := snyk.ScanData{
		Product: product.ProductOpenSource,
		Issues:  []snyk.Issue{mockCodeIssue},
	}
	// Act
	f.processResults(data)

	// Assert
	assert.Len(t, scanNotifier.SuccessCalls(), 1)
}

func Test_processResults_ShouldSendError(t *testing.T) {
	// Arrange
	testutil.UnitTest(t)

	f, scanNotifier := NewMockFolderWithScanNotifier(notification.NewNotifier())
	const filePath = "path1"
	mockCodeIssue := NewMockIssue("id1", filePath)

	data := snyk.ScanData{
		Product: product.ProductOpenSource,
		Issues: []snyk.Issue{
			mockCodeIssue,
		},
		Err: errors.New("test error"),
	} // Act
	f.processResults(data)

	// Assert
	assert.Empty(t, scanNotifier.SuccessCalls())
	assert.Len(t, scanNotifier.ErrorCalls(), 1)
}
func Test_processResults_ShouldSendAnalyticsToAPI(t *testing.T) {
	c := testutil.UnitTest(t)

	engineMock, gafConfig := setUpEngineMock(t, c)

	f, _ := NewMockFolderWithScanNotifier(notification.NewNotifier())
	const filePath = "path1"
	mockCodeIssue := NewMockIssue("id1", filePath)

	data := snyk.ScanData{
		Product: product.ProductOpenSource,
		Issues:  []snyk.Issue{mockCodeIssue},
	}

	engineMock.EXPECT().GetConfiguration().AnyTimes().Return(gafConfig)
	engineMock.EXPECT().InvokeWithInputAndConfig(localworkflows.WORKFLOWID_REPORT_ANALYTICS, gomock.Any(), gomock.Any()).
		// this captures the call parameters of the mocked call
		Do(func(id workflow.Identifier, workflowInputData []workflow.Data, config configuration.Configuration) {
			require.Equal(t, 1, len(workflowInputData))
			payloadBytes, ok := workflowInputData[0].GetPayload().([]byte)
			require.True(t, ok)

			var scanDoneEvent json_schemas.ScanDoneEvent
			err := json.Unmarshal(payloadBytes, &scanDoneEvent)
			require.NoError(t, err)
			require.Equal(t, "Snyk Open Source", scanDoneEvent.Data.Attributes.ScanType)
			require.Equal(t, 1, scanDoneEvent.Data.Attributes.UniqueIssueCount.Medium)
		})

	// Act
	f.processResults(data)
}

func Test_processResults_ShouldCountSeverityByProduct(t *testing.T) {
	c := testutil.UnitTest(t)

	engineMock, gafConfig := setUpEngineMock(t, c)

	f, _ := NewMockFolderWithScanNotifier(notification.NewNotifier())

	scanData := snyk.ScanData{
		Product:       product.ProductOpenSource,
		SeverityCount: make(map[product.Product]snyk.SeverityCount),
		Issues: []snyk.Issue{
			{Severity: snyk.Critical, Product: product.ProductOpenSource},
			{Severity: snyk.Critical, Product: product.ProductOpenSource},
			{Severity: snyk.High, Product: product.ProductOpenSource},
			{Severity: snyk.High, Product: product.ProductOpenSource},
			{Severity: snyk.Critical, Product: product.ProductInfrastructureAsCode}, // SeverityCount incremented by ScanData.Product
		},
	}

	engineMock.EXPECT().GetConfiguration().AnyTimes().Return(gafConfig)
	engineMock.EXPECT().InvokeWithInputAndConfig(localworkflows.WORKFLOWID_REPORT_ANALYTICS, gomock.Any(),
		gomock.Any()).Times(1)

	// Act
	f.processResults(scanData)

	// Assert
	require.Equal(t, 2, scanData.SeverityCount[product.ProductOpenSource].Critical)
}

func Test_IncrementSeverityCount(t *testing.T) {
	c := testutil.UnitTest(t)

	engineMock, gafConfig := setUpEngineMock(t, c)

	NewMockFolderWithScanNotifier(notification.NewNotifier())

	issue := snyk.Issue{
		Severity: snyk.Critical,
		Product:  product.ProductOpenSource,
	}

	scanData := snyk.ScanData{
		Product:       product.ProductOpenSource,
		SeverityCount: make(map[product.Product]snyk.SeverityCount),
		Issues:        []snyk.Issue{issue},
	}

	engineMock.EXPECT().GetConfiguration().AnyTimes().Return(gafConfig)
	engineMock.EXPECT().InvokeWithInputAndConfig(localworkflows.WORKFLOWID_REPORT_ANALYTICS, gomock.Any(), gomock.Any()).Times(0)

	// Act
	incrementSeverityCount(&scanData, scanData.Issues[0])

	// Assert
	require.Equal(t, 1, scanData.SeverityCount[product.ProductOpenSource].Critical)
}

func Test_initializeSeverityCountForProductWhenScanDataIsEmpty(t *testing.T) {
	c := testutil.UnitTest(t)

	engineMock, gafConfig := setUpEngineMock(t, c)

	NewMockFolderWithScanNotifier(notification.NewNotifier())

	engineMock.EXPECT().GetConfiguration().AnyTimes().Return(gafConfig)
	engineMock.EXPECT().InvokeWithInputAndConfig(localworkflows.WORKFLOWID_REPORT_ANALYTICS, gomock.Any(), gomock.Any()).Times(0)

	scanData := snyk.ScanData{}

	// Act
	initializeSeverityCountForProduct(&scanData, "")

	// Assert
	require.Equal(t, 0, scanData.SeverityCount["unknown"].Critical)
	require.Equal(t, 0, scanData.SeverityCount["unknown"].High)
	require.Equal(t, 0, scanData.SeverityCount["unknown"].Medium)
	require.Equal(t, 0, scanData.SeverityCount["unknown"].Low)
}

func NewMockFolder(notifier noti.Notifier) *Folder {
	return NewFolder("dummy", "dummy", snyk.NewTestScanner(), hover.NewFakeHoverService(), snyk.NewMockScanNotifier(), notifier)
}

func NewMockFolderWithScanNotifier(notifier noti.Notifier) (*Folder, *snyk.MockScanNotifier) {
	scanNotifier := snyk.NewMockScanNotifier()
	return NewFolder("dummy", "dummy", snyk.NewTestScanner(), hover.NewFakeHoverService(), scanNotifier, notifier), scanNotifier
}

func NewMockIssue(id, path string) snyk.Issue {
	return snyk.Issue{
		ID:               id,
		AffectedFilePath: path,
		Product:          product.ProductOpenSource,
		Severity:         snyk.Medium,
	}
}

func NewMockIssueWithSeverity(id, path string, severity snyk.Severity) snyk.Issue {
	issue := NewMockIssue(id, path)
	issue.Severity = severity

	return issue
}

func GetValueFromMap(m *xsync.MapOf[string, []snyk.Issue], key string) []snyk.Issue {
	value, _ := m.Load(key)
	return value
}

func setUpEngineMock(t *testing.T, c *config.Config) (*mocks.MockEngine, configuration.Configuration) {
	ctrl := gomock.NewController(t)
	mockEngine := mocks.NewMockEngine(ctrl)
	engineConfig := c.Engine().GetConfiguration()
	c.SetEngine(mockEngine)
	return mockEngine, engineConfig
}
