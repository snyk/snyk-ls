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

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestAddBundleHashToWorkspaceFolder(t *testing.T) {
	testutil.UnitTest(t)
	f := NewFolder(".", "Test", snyk.NewTestScanner(), hover.NewFakeHoverService())
	key := "bundleHash"
	value := "testHash"

	f.AddProductAttribute(snyk.ProductCode, key, value)

	assert.Equal(t, value, f.GetProductAttribute(snyk.ProductCode, key))
}

func Test_Scan_WhenCachedResults_shouldNotReScan(t *testing.T) {
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

func TestProcessResults_whenDifferentPaths_AddsToCache(t *testing.T) {
	testutil.UnitTest(t)
	f := NewFolder("dummy", "dummy", snyk.NewTestScanner(), hover.NewFakeHoverService())

	f.processResults([]snyk.Issue{
		{ID: "id1", AffectedFilePath: "path1"},
		{ID: "id2", AffectedFilePath: "path2"},
	})

	assert.Equal(t, 2, f.documentDiagnosticCache.Length())
	assert.NotNil(t, f.documentDiagnosticCache.Get("path1"))
	assert.NotNil(t, f.documentDiagnosticCache.Get("path2"))
	assert.Len(t, f.documentDiagnosticCache.Get("path1"), 1)
	assert.Len(t, f.documentDiagnosticCache.Get("path2"), 1)
}

func TestProcessResults_whenSamePaths_AddsToCache(t *testing.T) {
	testutil.UnitTest(t)
	f := NewFolder("dummy", "dummy", snyk.NewTestScanner(), hover.NewFakeHoverService())

	f.processResults([]snyk.Issue{
		{ID: "id1", AffectedFilePath: "path1"},
		{ID: "id2", AffectedFilePath: "path1"},
	})

	assert.Equal(t, 1, f.documentDiagnosticCache.Length())
	assert.NotNil(t, f.documentDiagnosticCache.Get("path1"))
	assert.Len(t, f.documentDiagnosticCache.Get("path1"), 2)
}

func TestProcessResults_whenDifferentPaths_AccumulatesIssues(t *testing.T) {
	testutil.UnitTest(t)
	f := NewFolder("dummy", "dummy", snyk.NewTestScanner(), hover.NewFakeHoverService())

	f.processResults([]snyk.Issue{
		{ID: "id1", AffectedFilePath: "path1"},
		{ID: "id2", AffectedFilePath: "path2"},
	})
	f.processResults([]snyk.Issue{{ID: "id3", AffectedFilePath: "path3"}})

	assert.Equal(t, 3, f.documentDiagnosticCache.Length())
	assert.NotNil(t, f.documentDiagnosticCache.Get("path1"))
	assert.NotNil(t, f.documentDiagnosticCache.Get("path2"))
	assert.NotNil(t, f.documentDiagnosticCache.Get("path3"))
}

func TestProcessResults_whenSamePaths_AccumulatesIssues(t *testing.T) {
	testutil.UnitTest(t)
	f := NewFolder("dummy", "dummy", snyk.NewTestScanner(), hover.NewFakeHoverService())

	f.processResults([]snyk.Issue{
		{ID: "id1", AffectedFilePath: "path1"},
		{ID: "id2", AffectedFilePath: "path1"},
	})
	f.processResults([]snyk.Issue{{ID: "id3", AffectedFilePath: "path1"}})

	assert.Equal(t, 1, f.documentDiagnosticCache.Length())
	assert.NotNil(t, f.documentDiagnosticCache.Get("path1"))
	assert.Len(t, f.documentDiagnosticCache.Get("path1"), 3)
}

func TestProcessResults_whenSamePathsAndDuplicateIssues_DeDuplicates(t *testing.T) {
	testutil.UnitTest(t)
	f := NewFolder("dummy", "dummy", snyk.NewTestScanner(), hover.NewFakeHoverService())

	f.processResults([]snyk.Issue{
		{ID: "id1", AffectedFilePath: "path1"},
		{ID: "id2", AffectedFilePath: "path1"},
	})
	f.processResults([]snyk.Issue{
		{ID: "id1", AffectedFilePath: "path1"},
		{ID: "id3", AffectedFilePath: "path1"},
	})

	assert.Equal(t, 1, f.documentDiagnosticCache.Length())
	assert.NotNil(t, f.documentDiagnosticCache.Get("path1"))
	assert.Len(t, f.documentDiagnosticCache.Get("path1"), 3)
}

func Test_ClearDiagnostics(t *testing.T) {
	testutil.UnitTest(t)
	f := NewFolder("dummy", "dummy", snyk.NewTestScanner(), hover.NewFakeHoverService())

	f.processResults([]snyk.Issue{
		{ID: "id1", AffectedFilePath: "path1"},
		{ID: "id2", AffectedFilePath: "path2"},
	})
	mtx := &sync.Mutex{}
	clearDiagnosticNotifications := 0
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

	assert.Equal(t, 0, f.documentDiagnosticCache.Length())
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
}
