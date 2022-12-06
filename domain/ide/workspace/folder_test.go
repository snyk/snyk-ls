/*
 * Copyright 2022 Snyk Ltd.
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
	"sync"
	"testing"
	"time"

	"github.com/puzpuzpuz/xsync"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/code"

	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_Scan_WhenCachedResults_shouldNotReScan(t *testing.T) {
	testutil.UnitTest(t)

	filePath, folderPath := code.FakeDiagnosticPath(t)
	scannerRecorder := snyk.NewTestScanner()
	scannerRecorder.Issues = []snyk.Issue{{AffectedFilePath: filePath}}
	f := NewFolder(folderPath, "Test", scannerRecorder, hover.NewFakeHoverService())
	ctx := context.Background()

	f.ScanFile(ctx, filePath)
	f.ScanFile(ctx, filePath)

	assert.Equal(t, 1, scannerRecorder.Calls())
}

// todo: unignore this test
func Test_Scan_WhenCachedResultsButNoIssues_shouldNotReScan(t *testing.T) {
	t.Skip("this feature is not implemented yet")
	filePath, folderPath := code.FakeDiagnosticPath(t)
	scannerRecorder := snyk.NewTestScanner()
	scannerRecorder.Issues = []snyk.Issue{}
	f := NewFolder(folderPath, "Test", scannerRecorder, hover.NewFakeHoverService())
	ctx := context.Background()

	f.ScanFile(ctx, filePath)
	f.ScanFile(ctx, filePath)

	assert.Equal(t, 1, scannerRecorder.Calls())
}

func Test_Scan_WhenNoIssues_shouldNotProcessResults(t *testing.T) {
	hoverRecorder := hover.NewFakeHoverService()
	testutil.UnitTest(t)
	f := NewFolder("dummy", "dummy", snyk.NewTestScanner(), hoverRecorder)

	f.processResults([]snyk.Issue{})

	assert.Equal(t, 0, hoverRecorder.Calls())
}

func TestProcessResults_SendsDiagnosticsAndHovers(t *testing.T) {
	t.Skipf("test this once we have uniform abstractions for hover & diagnostics")
	testutil.UnitTest(t)
	hoverService := hover.NewFakeHoverService()
	f := NewFolder("dummy", "dummy", snyk.NewTestScanner(), hoverService)

	issues := []snyk.Issue{
		{ID: "id1", AffectedFilePath: "path1"},
		{ID: "id2", AffectedFilePath: "path2"},
	}
	f.processResults(issues)
	// todo ideally there's a hover & diagnostic service that are symmetric and don't leak implementation details (e.g. channels)
	// assert.hoverService.GetAll()
}

func Test_ProcessResults_whenDifferentPaths_AddsToCache(t *testing.T) {
	testutil.UnitTest(t)
	f := NewFolder("dummy", "dummy", snyk.NewTestScanner(), hover.NewFakeHoverService())

	f.processResults([]snyk.Issue{
		{ID: "id1", AffectedFilePath: "path1"},
		{ID: "id2", AffectedFilePath: "path2"},
	})

	assert.Equal(t, 2, f.documentDiagnosticCache.Size())
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, "path1"))
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, "path2"))
	assert.Len(t, GetValueFromMap(f.documentDiagnosticCache, "path1"), 1)
	assert.Len(t, GetValueFromMap(f.documentDiagnosticCache, "path2"), 1)
}

func Test_ProcessResults_whenSamePaths_AddsToCache(t *testing.T) {
	testutil.UnitTest(t)
	f := NewFolder("dummy", "dummy", snyk.NewTestScanner(), hover.NewFakeHoverService())

	f.processResults([]snyk.Issue{
		{ID: "id1", AffectedFilePath: "path1"},
		{ID: "id2", AffectedFilePath: "path1"},
	})

	assert.Equal(t, 1, f.documentDiagnosticCache.Size())
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, "path1"))
	assert.Len(t, GetValueFromMap(f.documentDiagnosticCache, "path1"), 2)
}

func Test_ProcessResults_whenDifferentPaths_AccumulatesIssues(t *testing.T) {
	testutil.UnitTest(t)
	f := GetMockFolder()

	f.processResults([]snyk.Issue{
		{ID: "id1", AffectedFilePath: "path1"},
		{ID: "id2", AffectedFilePath: "path2"},
	})
	f.processResults([]snyk.Issue{{ID: "id3", AffectedFilePath: "path3"}})

	assert.Equal(t, 3, f.documentDiagnosticCache.Size())
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, "path1"))
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, "path2"))
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, "path3"))
}

func Test_ProcessResults_whenSamePaths_AccumulatesIssues(t *testing.T) {
	testutil.UnitTest(t)
	f := GetMockFolder()

	f.processResults([]snyk.Issue{
		{ID: "id1", AffectedFilePath: "path1"},
		{ID: "id2", AffectedFilePath: "path1"},
	})
	f.processResults([]snyk.Issue{{ID: "id3", AffectedFilePath: "path1"}})

	assert.Equal(t, 1, f.documentDiagnosticCache.Size())
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, "path1"))
	assert.Len(t, GetValueFromMap(f.documentDiagnosticCache, "path1"), 3)
}

func Test_ProcessResults_whenSamePathsAndDuplicateIssues_DeDuplicates(t *testing.T) {
	testutil.UnitTest(t)
	f := GetMockFolder()

	f.processResults([]snyk.Issue{
		{ID: "id1", AffectedFilePath: "path1"},
		{ID: "id2", AffectedFilePath: "path1"},
	})
	f.processResults([]snyk.Issue{
		{ID: "id1", AffectedFilePath: "path1"},
		{ID: "id3", AffectedFilePath: "path1"},
	})

	assert.Equal(t, 1, f.documentDiagnosticCache.Size())
	assert.NotNil(t, GetValueFromMap(f.documentDiagnosticCache, "path1"))
	assert.Len(t, GetValueFromMap(f.documentDiagnosticCache, "path1"), 3)
}

func TestProcessResults_whenFilteringSeverity_ProcessesOnlyFilteredIssues(t *testing.T) {
	testutil.UnitTest(t)

	config.SetCurrentConfig(config.New())
	severityFilter := lsp.NewSeverityFilter(true, false, true, false)
	config.CurrentConfig().SetSeverityFilter(severityFilter)

	f := GetMockFolder()

	f.processResults([]snyk.Issue{
		{ID: "id1", AffectedFilePath: "path1", Severity: snyk.Critical},
		{ID: "id2", AffectedFilePath: "path1", Severity: snyk.High},
		{ID: "id3", AffectedFilePath: "path1", Severity: snyk.Medium},
		{ID: "id4", AffectedFilePath: "path1", Severity: snyk.Low},
		{ID: "id5", AffectedFilePath: "path1", Severity: snyk.Critical},
	})

	mtx := &sync.Mutex{}
	var diagnostics []lsp.Diagnostic

	defer notification.DisposeListener()
	notification.CreateListener(func(event interface{}) {
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
	f := GetMockFolder()

	f.processResults([]snyk.Issue{
		{ID: "id1", AffectedFilePath: "path1"},
		{ID: "id2", AffectedFilePath: "path2"},
	})
	mtx := &sync.Mutex{}
	clearDiagnosticNotifications := 0

	defer notification.DisposeListener()
	notification.CreateListener(func(event interface{}) {
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
	notification.DisposeListener()
}

func Test_IsTrusted_shouldReturnFalseByDefault(t *testing.T) {
	testutil.UnitTest(t)
	config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)
	f := NewFolder("dummy", "dummy", snyk.NewTestScanner(), hover.NewFakeHoverService())
	assert.False(t, f.IsTrusted())
}

func Test_IsTrusted_shouldReturnTrueForPathContainedInTrustedFolders(t *testing.T) {
	testutil.UnitTest(t)
	config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)
	config.CurrentConfig().SetTrustedFolders([]string{"dummy"})
	f := NewFolder("dummy", "dummy", snyk.NewTestScanner(), hover.NewFakeHoverService())
	assert.True(t, f.IsTrusted())
}

func Test_IsTrusted_shouldReturnTrueForSubfolderOfTrustedFolders_Linux(t *testing.T) {
	testutil.IntegTest(t)
	testutil.NotOnWindows(t, "Unix/macOS file paths are incompatible with Windows")
	config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)
	config.CurrentConfig().SetTrustedFolders([]string{"/dummy"})
	f := NewFolder("/dummy/dummyF", "dummy", snyk.NewTestScanner(), hover.NewFakeHoverService())
	assert.True(t, f.IsTrusted())
}

func Test_IsTrusted_shouldReturnFalseForDifferentFolder(t *testing.T) {
	testutil.UnitTest(t)
	config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)
	config.CurrentConfig().SetTrustedFolders([]string{"/dummy"})
	f := NewFolder("/UntrustedPath", "dummy", snyk.NewTestScanner(), hover.NewFakeHoverService())
	assert.False(t, f.IsTrusted())
}

func Test_IsTrusted_shouldReturnTrueForSubfolderOfTrustedFolders(t *testing.T) {
	testutil.IntegTest(t)
	testutil.OnlyOnWindows(t, "Windows specific test")
	config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)
	config.CurrentConfig().SetTrustedFolders([]string{"c:\\dummy"})
	f := NewFolder("c:\\dummy\\dummyF", "dummy", snyk.NewTestScanner(), hover.NewFakeHoverService())
	assert.True(t, f.IsTrusted())
}

func Test_IsTrusted_shouldReturnTrueIfTrustFeatureDisabled(t *testing.T) {
	testutil.UnitTest(t) // disables trust feature
	f := NewFolder("c:\\dummy\\dummyF", "dummy", snyk.NewTestScanner(), hover.NewFakeHoverService())
	assert.True(t, f.IsTrusted())
}

func Test_FilterCachedDiagnostics_filtersDisabledSeverity(t *testing.T) {
	testutil.UnitTest(t)

	// arrange
	filePath, folderPath := code.FakeDiagnosticPath(t)
	scannerRecorder := snyk.NewTestScanner()
	scannerRecorder.Issues = []snyk.Issue{
		{AffectedFilePath: filePath, Severity: snyk.Critical},
		{AffectedFilePath: filePath, Severity: snyk.High},
		{AffectedFilePath: filePath, Severity: snyk.Medium},
		{AffectedFilePath: filePath, Severity: snyk.Low},
	}

	f := NewFolder(folderPath, "Test", scannerRecorder, hover.NewFakeHoverService())
	ctx := context.Background()

	config.CurrentConfig().SetSeverityFilter(lsp.NewSeverityFilter(true, true, false, false))

	// act
	f.ScanFile(ctx, filePath)
	filteredDiagnostics := f.filterCachedDiagnostics()

	// assert
	assert.Len(t, filteredDiagnostics[filePath], 2)
	assert.Contains(t, filteredDiagnostics[filePath], snyk.Issue{AffectedFilePath: filePath, Severity: snyk.Critical})
	assert.Contains(t, filteredDiagnostics[filePath], snyk.Issue{AffectedFilePath: filePath, Severity: snyk.High})
}

func Test_ClearDiagnosticsByProduct(t *testing.T) {
	// Arrange
	testutil.UnitTest(t)
	f := GetMockFolder()
	const filePath = "path1"
	mockCodeIssue := GetMockIssue("id1", filePath)
	mockCodeIssue.Product = product.ProductCode
	mockIacIssue := GetMockIssue("id2", filePath)
	mockIacIssue.Product = product.ProductInfrastructureAsCode
	f.processResults([]snyk.Issue{
		mockIacIssue,
		mockCodeIssue,
	})
	const expectedIssuesCountAfterRemoval = 1

	// Act
	f.ClearDiagnosticsByProduct(product.ProductCode)

	// Assert
	issues := f.AllIssuesFor(filePath)
	t.Run("Does not return diagnostics of that type", func(t *testing.T) {
		for _, issue := range issues {
			assert.NotEqual(t, product.ProductCode, issue.Product)
		}
	})

	t.Run("Return diagnostics of other types", func(t *testing.T) {
		assert.Len(t, issues, expectedIssuesCountAfterRemoval)
	})
}

func GetMockFolder() *Folder {
	return NewFolder("dummy", "dummy", snyk.NewTestScanner(), hover.NewFakeHoverService())
}

func GetMockIssue(id, path string) snyk.Issue {
	return snyk.Issue{
		ID:               id,
		AffectedFilePath: path,
	}
}

func GetValueFromMap(m *xsync.MapOf[string, []snyk.Issue], key string) []snyk.Issue {
	value, _ := m.Load(key)
	return value
}
