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
	"sync"
	"testing"
	"time"

	"github.com/puzpuzpuz/xsync"
	"github.com/stretchr/testify/assert"

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
	scannerRecorder := snyk.NewTestScanner()

	scannerRecorder.Issues = []snyk.Issue{NewMockIssue("1", filePath)}
	f := NewFolder(folderPath, "Test", scannerRecorder, hover.NewFakeHoverService(), snyk.NewMockScanNotifier(), notification.NewNotifier())
	ctx := context.Background()

	f.ScanFile(ctx, filePath)
	f.ScanFile(ctx, filePath)

	assert.Equal(t, 1, scannerRecorder.Calls())
}

func Test_Scan_WhenNoIssues_shouldNotProcessResults(t *testing.T) {
	hoverRecorder := hover.NewFakeHoverService()
	testutil.UnitTest(t)
	f := NewFolder("dummy", "dummy", snyk.NewTestScanner(), hoverRecorder, snyk.NewMockScanNotifier(), notification.NewNotifier())

	f.processResults("unknown", []snyk.Issue{}, nil)

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
	f.processResults(product.ProductOpenSource, issues, nil)
	// todo ideally there's a hover & diagnostic service that are symmetric and don't leak implementation details (e.g. channels)
	// assert.hoverService.GetAll()
}

func Test_ProcessResults_whenDifferentPaths_AddsToCache(t *testing.T) {
	testutil.UnitTest(t)
	f := NewFolder("dummy", "dummy", snyk.NewTestScanner(), hover.NewFakeHoverService(), snyk.NewMockScanNotifier(), notification.NewNotifier())

	f.processResults(product.ProductOpenSource, []snyk.Issue{
		NewMockIssue("id1", "path1"),
		NewMockIssue("id2", "path2"),
	}, nil)

	assert.Equal(t, 2, f.documentDiagnosticCache.Size())
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, "path1"))
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, "path2"))
	assert.Len(t, GetValueFromMap(f.documentDiagnosticCache, "path1"), 1)
	assert.Len(t, GetValueFromMap(f.documentDiagnosticCache, "path2"), 1)
}

func Test_ProcessResults_whenSamePaths_AddsToCache(t *testing.T) {
	testutil.UnitTest(t)
	f := NewFolder("dummy", "dummy", snyk.NewTestScanner(), hover.NewFakeHoverService(), snyk.NewMockScanNotifier(), notification.NewNotifier())

	f.processResults(product.ProductOpenSource, []snyk.Issue{
		NewMockIssue("id1", "path1"),
		NewMockIssue("id2", "path1"),
	}, nil)

	assert.Equal(t, 1, f.documentDiagnosticCache.Size())
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, "path1"))
	assert.Len(t, GetValueFromMap(f.documentDiagnosticCache, "path1"), 2)
}

func Test_ProcessResults_whenDifferentPaths_AccumulatesIssues(t *testing.T) {
	testutil.UnitTest(t)
	f := NewMockFolder(notification.NewNotifier())

	f.processResults(product.ProductOpenSource, []snyk.Issue{
		NewMockIssue("id1", "path1"),
		NewMockIssue("id2", "path2"),
	}, nil)
	f.processResults(product.ProductOpenSource, []snyk.Issue{NewMockIssue("id3", "path3")}, nil)

	assert.Equal(t, 3, f.documentDiagnosticCache.Size())
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, "path1"))
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, "path2"))
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, "path3"))
}

func Test_ProcessResults_whenSamePaths_AccumulatesIssues(t *testing.T) {
	testutil.UnitTest(t)
	f := NewMockFolder(notification.NewNotifier())

	f.processResults(product.ProductOpenSource, []snyk.Issue{
		NewMockIssue("id1", "path1"),
		NewMockIssue("id2", "path1"),
	}, nil)
	f.processResults(product.ProductOpenSource, []snyk.Issue{NewMockIssue("id3", "path1")}, nil)

	assert.Equal(t, 1, f.documentDiagnosticCache.Size())
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, "path1"))
	assert.Len(t, GetValueFromMap(f.documentDiagnosticCache, "path1"), 3)
}

func Test_ProcessResults_whenSamePathsAndDuplicateIssues_DeDuplicates(t *testing.T) {
	testutil.UnitTest(t)
	f := NewMockFolder(notification.NewNotifier())

	f.processResults(product.ProductOpenSource, []snyk.Issue{
		NewMockIssue("id1", "path1"),
		NewMockIssue("id2", "path1"),
	}, nil)
	f.processResults(product.ProductOpenSource, []snyk.Issue{
		NewMockIssue("id1", "path1"),
		NewMockIssue("id3", "path1"),
	}, nil)

	assert.Equal(t, 1, f.documentDiagnosticCache.Size())
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, "path1"))
	assert.Len(t, GetValueFromMap(f.documentDiagnosticCache, "path1"), 3)
}

func TestProcessResults_whenFilteringSeverity_ProcessesOnlyFilteredIssues(t *testing.T) {
	testutil.UnitTest(t)

	config.SetCurrentConfig(config.New())
	severityFilter := lsp.NewSeverityFilter(true, false, true, false)
	config.CurrentConfig().SetSeverityFilter(severityFilter)

	f := NewMockFolder(notification.NewNotifier())

	f.processResults(product.ProductOpenSource, []snyk.Issue{
		NewMockIssueWithSeverity("id1", "path1", snyk.Critical),
		NewMockIssueWithSeverity("id2", "path1", snyk.High),
		NewMockIssueWithSeverity("id3", "path1", snyk.Medium),
		NewMockIssueWithSeverity("id4", "path1", snyk.Low),
		NewMockIssueWithSeverity("id5", "path1", snyk.Critical),
	}, nil)

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

	f.processResults(product.ProductOpenSource, []snyk.Issue{
		NewMockIssue("id1", "path1"),
		NewMockIssue("id2", "path2"),
	}, nil)
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
	f.processResults(product.ProductOpenSource, []snyk.Issue{
		mockIacIssue,
		mockCodeIssue,
	}, nil)
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

	// Act
	f.processResults(product.ProductOpenSource, []snyk.Issue{
		mockCodeIssue,
	}, nil)

	// Assert
	assert.Len(t, scanNotifier.SuccessCalls(), 1)
}

func Test_processResults_ShouldSendError(t *testing.T) {
	// Arrange
	testutil.UnitTest(t)

	f, scanNotifier := NewMockFolderWithScanNotifier(notification.NewNotifier())
	const filePath = "path1"
	mockCodeIssue := NewMockIssue("id1", filePath)

	// Act
	f.processResults(product.ProductOpenSource, []snyk.Issue{
		mockCodeIssue,
	}, errors.New("test error"))

	// Assert
	assert.Empty(t, scanNotifier.SuccessCalls())
	assert.Len(t, scanNotifier.ErrorCalls(), 1)
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
