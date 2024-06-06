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

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/puzpuzpuz/xsync/v3"
	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
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
	"github.com/snyk/snyk-ls/internal/util"
)

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

func Test_ProcessResults_whenDifferentPaths_AddsToCache(t *testing.T) {
	testutil.UnitTest(t)
	f := NewFolder("dummy", "dummy", snyk.NewTestScanner(), hover.NewFakeHoverService(), snyk.NewMockScanNotifier(), notification.NewNotifier())

	path1 := filepath.Join(f.path, "path1")
	path2 := filepath.Join(f.path, "path2")
	data := snyk.ScanData{
		Product: product.ProductOpenSource,
		Issues: []snyk.Issue{
			NewMockIssue("id1", path1),
			NewMockIssue("id2", path2),
		},
	}
	f.ScanFolder(context.Background())
	f.processResults(data)

	assert.Equal(t, 2, f.documentDiagnosticCache.Size())
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, path1))
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, path2))
	assert.Len(t, GetValueFromMap(f.documentDiagnosticCache, path1), 1)
	assert.Len(t, GetValueFromMap(f.documentDiagnosticCache, path2), 1)
}

func Test_ProcessResults_whenSamePaths_AddsToCache(t *testing.T) {
	testutil.UnitTest(t)
	f := NewFolder("dummy", "dummy", snyk.NewTestScanner(), hover.NewFakeHoverService(), snyk.NewMockScanNotifier(), notification.NewNotifier())

	filePath := "dummy/path1"
	data := snyk.ScanData{
		Product: product.ProductOpenSource,
		Issues: []snyk.Issue{
			NewMockIssue("id1", filePath),
			NewMockIssue("id2", filePath),
		},
	}
	f.processResults(data)

	assert.Equal(t, 1, len(f.Issues()))
	assert.Len(t, f.IssuesForFile(filePath), 2)
}

func Test_ProcessResults_whenDifferentPaths_AccumulatesIssues(t *testing.T) {
	testutil.UnitTest(t)
	f := NewMockFolder(notification.NewNotifier())

	path1 := filepath.Join(f.path, "path1")
	path2 := filepath.Join(f.path, "path2")
	path3 := filepath.Join(f.path, "path3")
	data := snyk.ScanData{
		Product: product.ProductOpenSource,
		Issues: []snyk.Issue{
			NewMockIssue("id1", path1),
			NewMockIssue("id2", path2),
			NewMockIssue("id3", path3),
		},
	}
	f.processResults(data)

	assert.Len(t, f.Issues(), 3)
	assert.Len(t, f.IssuesForFile(path1), 1)
	assert.Len(t, f.IssuesForFile(path2), 1)
	assert.Len(t, f.IssuesForFile(path3), 1)
}

func Test_ProcessResults_whenSamePaths_AccumulatesIssues(t *testing.T) {
	testutil.UnitTest(t)
	f := NewMockFolder(notification.NewNotifier())

	path1 := filepath.Join(f.path, "path1")
	data := snyk.ScanData{
		Product: product.ProductOpenSource,
		Issues: []snyk.Issue{
			NewMockIssue("id1", path1),
			NewMockIssue("id2", path1),
			NewMockIssue("id3", path1),
		},
	}
	f.processResults(data)

	assert.Len(t, f.Issues(), 1)
	issuesForFile := f.IssuesForFile(path1)
	assert.NotNil(t, issuesForFile)
	assert.Len(t, issuesForFile, 3)
}

func Test_ProcessResults_whenSamePathsAndDuplicateIssues_DeDuplicates(t *testing.T) {
	testutil.UnitTest(t)
	f := NewMockFolder(notification.NewNotifier())

	path1 := filepath.Join(f.path, "path1")
	path2 := filepath.Join(f.path, "path2")
	issue1 := NewMockIssue("id1", path1)
	issue2 := NewMockIssue("id2", path1)
	issue3 := NewMockIssue("id3", path1)
	issue4 := NewMockIssue("id1", path2)
	issue5 := NewMockIssue("id3", path2)

	data := snyk.ScanData{
		Product: product.ProductOpenSource,
		Issues: []snyk.Issue{
			issue1,
			issue1,
			issue2,
			issue3,
			issue4,
			issue5,
		},
	}
	f.processResults(data)

	assert.Len(t, f.Issues(), 2)
	issuesForFile := f.IssuesForFile(path1)
	assert.NotNil(t, issuesForFile)
	assert.Len(t, issuesForFile, 3)
}

func TestProcessResults_whenFilteringSeverity_ProcessesOnlyFilteredIssues(t *testing.T) {
	testutil.UnitTest(t)
	c := config.New()
	config.SetCurrentConfig(c)

	severityFilter := lsp.NewSeverityFilter(true, false, true, false)
	config.CurrentConfig().SetSeverityFilter(severityFilter)

	f := NewMockFolder(notification.NewNotifier())

	path1 := filepath.Join(f.path, "path1")
	data := snyk.ScanData{
		Product: product.ProductOpenSource,
		Issues: []snyk.Issue{
			NewMockIssueWithSeverity("id1", filepath.Join(f.path, path1), snyk.Critical),
			NewMockIssueWithSeverity("id2", filepath.Join(f.path, path1), snyk.High),
			NewMockIssueWithSeverity("id3", filepath.Join(f.path, path1), snyk.Medium),
			NewMockIssueWithSeverity("id4", filepath.Join(f.path, path1), snyk.Low),
			NewMockIssueWithSeverity("id5", filepath.Join(f.path, path1), snyk.Critical),
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

func Test_Clear(t *testing.T) {
	testutil.UnitTest(t)
	f := NewMockFolder(notification.NewNotifier())

	path1 := filepath.Join(f.path, "path1")
	path2 := filepath.Join(f.path, "path2")
	data := snyk.ScanData{
		Product: product.ProductOpenSource,
		Issues: []snyk.Issue{
			NewMockIssue("id1", path1),
			NewMockIssue("id2", path2),
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

	criticalIssue := snyk.Issue{AffectedFilePath: filePath, Severity: snyk.Critical,
		Product: product.ProductOpenSource, AdditionalData: snyk.OssIssueData{Key: util.Result(uuid.NewUUID()).String()}}

	highIssue := snyk.Issue{
		AffectedFilePath: filePath,
		Severity:         snyk.High,
		Product:          product.ProductOpenSource,
		AdditionalData:   snyk.OssIssueData{Key: util.Result(uuid.NewUUID()).String()},
	}
	mediumIssue := snyk.Issue{
		AffectedFilePath: filePath,
		Severity:         snyk.Medium,
		Product:          product.ProductOpenSource,
		AdditionalData:   snyk.OssIssueData{Key: util.Result(uuid.NewUUID()).String()},
	}
	lowIssue := snyk.Issue{
		AffectedFilePath: filePath,
		Severity:         snyk.Low,
		Product:          product.ProductOpenSource,
		AdditionalData:   snyk.OssIssueData{Key: util.Result(uuid.NewUUID()).String()},
	}

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
	filteredDiagnostics := f.filterDiagnostics(f.Issues())

	// assert
	assert.Len(t, filteredDiagnostics[filePath], 2)
	assert.Contains(t, filteredDiagnostics[filePath], criticalIssue)
	assert.Contains(t, filteredDiagnostics[filePath], highIssue)
}

func Test_ClearDiagnosticsByIssueType(t *testing.T) {
	// Arrange
	testutil.UnitTest(t)
	f := NewMockFolder(notification.NewNotifier())
	filePath := filepath.Join(f.path, "path1")
	mockOpenSourceIssue := NewMockIssue("id1", filePath)
	removedIssueType := product.FilterableIssueTypeOpenSource
	mockOpenSourceIssue.Product = product.ProductOpenSource
	mockIacIssue := NewMockIssue("id2", filePath)
	mockIacIssue.Product = product.ProductInfrastructureAsCode
	data := snyk.ScanData{
		Product: product.ProductOpenSource,
		Issues: []snyk.Issue{
			mockIacIssue,
			mockOpenSourceIssue,
		},
	}
	f.processResults(data)
	const expectedIssuesCountAfterRemoval = 1

	// Act
	f.ClearDiagnosticsByIssueType(removedIssueType)

	// Assert
	issues := f.IssuesForFile(filePath)
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
	var path = "path1"
	mockCodeIssue := NewMockIssue("id1", filepath.Join(f.path, path))

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

	gafConfig := configuration.NewInMemory()
	engineMock := workflow.NewWorkFlowEngine(gafConfig)
	c.SetEngine(engineMock)

	f, _ := NewMockFolderWithScanNotifier(notification.NewNotifier())
	filePath := filepath.Join(f.path, "path1")
	mockCodeIssue := NewMockIssue("id1", filePath)

	data := snyk.ScanData{
		Product: product.ProductOpenSource,
		Issues:  []snyk.Issue{mockCodeIssue},
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
			require.Equal(t, []string{product.ToProductCodename(data.Product), "test"}, *actualV2InstrumentationObject.Data.Attributes.Interaction.Categories)
			require.Equal(t, "Analytics", actualV2InstrumentationObject.Data.Type)

			close(entered)
			return nil, nil
		})

	assert.NoError(t, err)

	err = engineMock.Init()
	assert.NoError(t, err)

	// Act
	f.processResults(data)
	maxWaitTime := 10 * time.Second

	select {
	case <-entered:
	case <-time.After(maxWaitTime):
		t.Fatalf("time out. condition wasn't met. current timeout value is: %s", maxWaitTime)
	}
}

func Test_processResults_ShouldCountSeverityByProduct(t *testing.T) {
	c := testutil.UnitTest(t)

	engineMock, gafConfig := setUpEngineMock(t, c)

	f, _ := NewMockFolderWithScanNotifier(notification.NewNotifier())

	filePath := filepath.Join(f.Path(), "dummy.java")
	scanData := snyk.ScanData{
		Product: product.ProductOpenSource,
		Issues: []snyk.Issue{
			{Severity: snyk.Critical, Product: product.ProductOpenSource, AffectedFilePath: filePath, AdditionalData: snyk.OssIssueData{Key: util.Result(uuid.NewUUID()).String()}},
			{Severity: snyk.Critical, Product: product.ProductOpenSource, AffectedFilePath: filePath, AdditionalData: snyk.OssIssueData{Key: util.Result(uuid.NewUUID()).String()}},
			{Severity: snyk.Critical, IsIgnored: true, Product: product.ProductOpenSource, AffectedFilePath: filePath, AdditionalData: snyk.OssIssueData{Key: util.Result(uuid.NewUUID()).String()}},
			{Severity: snyk.High, Product: product.ProductOpenSource, AffectedFilePath: filePath, AdditionalData: snyk.OssIssueData{Key: util.Result(uuid.NewUUID()).String()}},
			{Severity: snyk.High, Product: product.ProductOpenSource, AffectedFilePath: filePath, AdditionalData: snyk.OssIssueData{Key: util.Result(uuid.NewUUID()).String()}},
		},
	}

	engineMock.EXPECT().GetConfiguration().AnyTimes().Return(gafConfig)
	engineMock.EXPECT().GetWorkflows().AnyTimes()
	engineMock.EXPECT().InvokeWithInputAndConfig(localworkflows.WORKFLOWID_REPORT_ANALYTICS, gomock.Any(),
		gomock.Any()).Times(1)

	// Act
	f.processResults(scanData)

	// Assert
	require.NotEmpty(t, scanData.GetSeverityIssueCounts())
	require.Equal(t, product.ProductOpenSource, scanData.Product)
	require.Equal(t, 3, scanData.GetSeverityIssueCounts()[snyk.Critical].Total)
	require.Equal(t, 2, scanData.GetSeverityIssueCounts()[snyk.Critical].Open)
	require.Equal(t, 1, scanData.GetSeverityIssueCounts()[snyk.Critical].Ignored)

	// wait for async analytics sending
	time.Sleep(time.Second)
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
		AdditionalData:   snyk.OssIssueData{Key: util.Result(uuid.NewUUID()).String()},
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
	t.Helper()
	ctrl := gomock.NewController(t)
	mockEngine := mocks.NewMockEngine(ctrl)
	engineConfig := c.Engine().GetConfiguration()
	c.SetEngine(mockEngine)
	return mockEngine, engineConfig
}
