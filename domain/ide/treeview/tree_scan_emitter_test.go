/*
 * © 2026 Snyk Limited
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

package treeview

import (
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/testutil/workspaceutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestTreeScanStateEmitter_Emit_SendsTreeViewNotification(t *testing.T) {
	engine := testutil.UnitTest(t)
	notif := notification.NewNotifier()

	var mu sync.Mutex
	var receivedPayload any
	notif.CreateListener(func(params any) {
		mu.Lock()
		defer mu.Unlock()
		receivedPayload = params
	})
	t.Cleanup(func() { notif.DisposeListener() })

	emitter, err := NewTreeScanStateEmitter(engine.GetConfiguration(), engine.GetLogger(), notif)
	require.NoError(t, err)
	t.Cleanup(emitter.Dispose)

	emitter.Emit(scanstates.StateSnapshot{
		AnyScanInProgressWorkingDirectory: true,
	})

	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return receivedPayload != nil
	}, 2*time.Second, 50*time.Millisecond)

	mu.Lock()
	treeView, ok := receivedPayload.(types.TreeView)
	mu.Unlock()
	require.True(t, ok, "payload should be types.TreeView")
	assert.Contains(t, treeView.TreeViewHtml, "<!DOCTYPE html>")
}

func TestTreeScanStateEmitter_Emit_FeedbackBannerReflectsConfig(t *testing.T) {
	t.Run("dismissed omits the banner", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		config.SetFeedbackBannerDismissed(engine.GetConfiguration())
		html := emitAndCaptureHTML(t, engine.GetConfiguration(), engine.GetLogger())
		assert.NotContains(t, html, `id="feedbackBanner"`)
	})

	t.Run("interacted renders the banner visible", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		config.SetFeedbackBannerInteracted(engine.GetConfiguration())
		html := emitAndCaptureHTML(t, engine.GetConfiguration(), engine.GetLogger())
		assert.Contains(t, html, `id="feedbackBanner"`)
		assert.NotContains(t, html, `id="feedbackBanner" hidden>`)
	})
}

// emitAndCaptureHTML runs one emit cycle and returns the rendered tree HTML.
func emitAndCaptureHTML(t *testing.T, conf configuration.Configuration, logger *zerolog.Logger) string {
	t.Helper()
	notif := notification.NewNotifier()
	var mu sync.Mutex
	var receivedPayload any
	notif.CreateListener(func(params any) {
		mu.Lock()
		defer mu.Unlock()
		receivedPayload = params
	})
	t.Cleanup(func() { notif.DisposeListener() })

	emitter, err := NewTreeScanStateEmitter(conf, logger, notif)
	require.NoError(t, err)
	t.Cleanup(emitter.Dispose)

	emitter.Emit(scanstates.StateSnapshot{AnyScanInProgressWorkingDirectory: true})

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return receivedPayload != nil
	}, 2*time.Second, 50*time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	treeView, ok := receivedPayload.(types.TreeView)
	require.True(t, ok, "payload should be types.TreeView")
	return treeView.TreeViewHtml
}

func TestTreeScanStateEmitter_Emit_ScanInProgress_HasScanningInProductNode(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), true)

	// Set up workspace so product nodes are rendered.
	workspaceutil.SetupWorkspace(t, engine, types.FilePath("/project"))

	notif := notification.NewNotifier()

	var mu sync.Mutex
	var receivedPayload any
	notif.CreateListener(func(params any) {
		mu.Lock()
		defer mu.Unlock()
		receivedPayload = params
	})
	t.Cleanup(func() { notif.DisposeListener() })

	emitter, err := NewTreeScanStateEmitter(engine.GetConfiguration(), engine.GetLogger(), notif)
	require.NoError(t, err)
	t.Cleanup(emitter.Dispose)

	folderKey := types.PathKey("/project")
	emitter.Emit(scanstates.StateSnapshot{
		AnyScanInProgressWorkingDirectory: true,
		ProductScanStates: map[types.FilePath]map[product.Product]bool{
			folderKey: {product.ProductCode: true},
		},
	})

	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return receivedPayload != nil
	}, 2*time.Second, 50*time.Millisecond)

	mu.Lock()
	treeView := receivedPayload.(types.TreeView)
	mu.Unlock()
	assert.Contains(t, treeView.TreeViewHtml, "Scanning...", "scanning indicator should be in product node description, not global banner")
	assert.NotContains(t, treeView.TreeViewHtml, `id="scanStatus"`, "global scanning banner element should be removed")
}

func TestTreeScanStateEmitter_Emit_ConcurrentCallsNoRace(t *testing.T) {
	engine := testutil.UnitTest(t)
	workspaceutil.SetupWorkspace(t, engine, types.FilePath("/project"))

	notif := notification.NewNotifier()
	notif.CreateListener(func(params any) {})
	t.Cleanup(func() { notif.DisposeListener() })

	emitter, err := NewTreeScanStateEmitter(engine.GetConfiguration(), engine.GetLogger(), notif)
	require.NoError(t, err)
	t.Cleanup(emitter.Dispose)

	folderKey := types.PathKey("/project")
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			emitter.Emit(scanstates.StateSnapshot{
				ProductScanStates: map[types.FilePath]map[product.Product]bool{
					folderKey: {product.ProductCode: true},
				},
			})
		}()
	}
	wg.Wait()
}

func TestTreeScanStateEmitter_Emit_PerProductScanStatus(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), true)

	// Set up a workspace with a folder so that product nodes are generated.
	workspaceutil.SetupWorkspace(t, engine, types.FilePath("/project"))

	notif := notification.NewNotifier()

	var mu sync.Mutex
	var receivedPayload any
	notif.CreateListener(func(params any) {
		mu.Lock()
		defer mu.Unlock()
		receivedPayload = params
	})
	t.Cleanup(func() { notif.DisposeListener() })

	emitter, err := NewTreeScanStateEmitter(engine.GetConfiguration(), engine.GetLogger(), notif)
	require.NoError(t, err)
	t.Cleanup(emitter.Dispose)

	folderKey := types.PathKey("/project")
	emitter.Emit(scanstates.StateSnapshot{
		AnyScanInProgressWorkingDirectory: true,
		ProductScanStates: map[types.FilePath]map[product.Product]bool{
			folderKey: {
				product.ProductCode:                 true,
				product.ProductOpenSource:           false,
				product.ProductInfrastructureAsCode: false,
			},
		},
	})

	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return receivedPayload != nil
	}, 2*time.Second, 50*time.Millisecond)

	mu.Lock()
	treeView := receivedPayload.(types.TreeView)
	mu.Unlock()
	assert.Contains(t, treeView.TreeViewHtml, "Scanning...", "Code product node should show Scanning... since its scan is in progress")
}

func TestTreeScanStateEmitter_Dispose_StopsRenderLoop(t *testing.T) {
	engine := testutil.UnitTest(t)
	notif := notification.NewNotifier()
	notif.CreateListener(func(params any) {})
	t.Cleanup(func() { notif.DisposeListener() })

	emitter, err := NewTreeScanStateEmitter(engine.GetConfiguration(), engine.GetLogger(), notif)
	require.NoError(t, err)

	emitter.Dispose()
	// Double-dispose must not panic.
	emitter.Dispose()

	// Emit after Dispose must not block or panic.
	emitter.Emit(scanstates.StateSnapshot{AnyScanInProgressWorkingDirectory: true})
}

func TestAggregateSeverityFilters(t *testing.T) {
	t.Run("single folder is never mixed", func(t *testing.T) {
		f := types.NewSeverityFilter(true, false, true, false)
		sev, mixed := aggregateSeverityFilters([]types.SeverityFilter{f})
		assert.Equal(t, f, sev)
		assert.Equal(t, MixedSeverity{}, mixed)
	})

	t.Run("all folders agree", func(t *testing.T) {
		f := types.NewSeverityFilter(true, true, false, false)
		sev, mixed := aggregateSeverityFilters([]types.SeverityFilter{f, f, f})
		assert.Equal(t, f, sev)
		assert.Equal(t, MixedSeverity{}, mixed)
	})

	t.Run("disagreement marks only the differing severities mixed", func(t *testing.T) {
		_, mixed := aggregateSeverityFilters([]types.SeverityFilter{
			types.NewSeverityFilter(true, true, true, true),
			types.NewSeverityFilter(false, true, true, false),
		})
		assert.True(t, mixed.Critical, "critical differs -> mixed")
		assert.False(t, mixed.High, "high agrees")
		assert.False(t, mixed.Medium, "medium agrees")
		assert.True(t, mixed.Low, "low differs -> mixed")
	})
}

// TestTreeScanStateEmitter_FolderLevelIssueViewOptions verifies that the info-node message
// reflects folder-level IssueViewOptions overrides rather than the global setting.
// Regression for: global open+ignored disabled, folder-level open+ignored enabled →
// "Open and Ignored issues are disabled!" must NOT appear.
func TestTreeScanStateEmitter_FolderLevelIssueViewOptions(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()

	// Enable products so product nodes (and their info nodes) are rendered.
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)

	// Global: both open and ignored issues disabled.
	conf.Set(configresolver.UserGlobalKey(types.SettingIssueViewOpenIssues), false)
	conf.Set(configresolver.UserGlobalKey(types.SettingIssueViewIgnoredIssues), false)

	// SnykCodeConsistentIgnores must be true for the IVO branch in zeroIssuesText to execute.
	// Without it, zeroIssuesText early-returns "✅ Congrats! No issues found!" regardless of IVO.
	ffSvc := featureflag.NewFakeService()
	ffSvc.Override(featureflag.SnykCodeConsistentIgnores, true)

	folderPath := types.FilePath("/project-folder-ivo")
	workspaceutil.SetupWorkspaceWithFeatureFlags(t, engine, ffSvc, folderPath)

	// Folder-level override: both enabled (takes precedence over global).
	folderKey := string(types.PathKey(folderPath))
	conf.Set(configresolver.UserFolderKey(folderKey, types.SettingIssueViewOpenIssues), &configresolver.LocalConfigField{Value: true, Changed: true})
	conf.Set(configresolver.UserFolderKey(folderKey, types.SettingIssueViewIgnoredIssues), &configresolver.LocalConfigField{Value: true, Changed: true})

	notif := notification.NewNotifier()
	var mu sync.Mutex
	var receivedPayload any
	notif.CreateListener(func(params any) {
		mu.Lock()
		defer mu.Unlock()
		receivedPayload = params
	})
	t.Cleanup(func() { notif.DisposeListener() })

	emitter, err := NewTreeScanStateEmitter(conf, engine.GetLogger(), notif)
	require.NoError(t, err)
	t.Cleanup(emitter.Dispose)

	// Mark the Code product scan as completed (false = not in progress) so that info nodes are rendered.
	// Without a scan-registered entry the product node renders no children and neither assertion would fire.
	emitter.Emit(scanstates.StateSnapshot{
		ProductScanStates: map[types.FilePath]map[product.Product]bool{
			types.PathKey(folderPath): {product.ProductCode: false},
		},
	})

	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return receivedPayload != nil
	}, 2*time.Second, 50*time.Millisecond)

	mu.Lock()
	treeView := receivedPayload.(types.TreeView)
	mu.Unlock()
	assert.NotContains(t, treeView.TreeViewHtml, "Open and Ignored issues are disabled!",
		"folder-level enabled override must suppress the disabled info message")
	assert.Contains(t, treeView.TreeViewHtml, "No issues found",
		"product node must still render a non-empty info message so the NotContains above is non-vacuous")
}

// TestTreeScanStateEmitter_GlobalDisabledIVO_ShowsDisabledMessage is the positive counterpart
// to TestTreeScanStateEmitter_FolderLevelIssueViewOptions: when SnykCodeConsistentIgnores is
// enabled but there is NO folder-level override, the global disabled setting must produce the
// "Open and Ignored issues are disabled!" info-node message.
func TestTreeScanStateEmitter_GlobalDisabledIVO_ShowsDisabledMessage(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()

	// Enable products so product nodes (and their info nodes) are rendered.
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)

	// Global: both open and ignored issues disabled.
	conf.Set(configresolver.UserGlobalKey(types.SettingIssueViewOpenIssues), false)
	conf.Set(configresolver.UserGlobalKey(types.SettingIssueViewIgnoredIssues), false)

	// SnykCodeConsistentIgnores must be true for the IVO branch in zeroIssuesText to execute.
	ffSvc := featureflag.NewFakeService()
	ffSvc.Override(featureflag.SnykCodeConsistentIgnores, true)

	// No folder-level override: global disabled applies.
	folderPath := types.FilePath("/project-global-disabled-ivo")
	workspaceutil.SetupWorkspaceWithFeatureFlags(t, engine, ffSvc, folderPath)

	notif := notification.NewNotifier()
	var mu sync.Mutex
	var receivedPayload any
	notif.CreateListener(func(params any) {
		mu.Lock()
		defer mu.Unlock()
		receivedPayload = params
	})
	t.Cleanup(func() { notif.DisposeListener() })

	emitter, err := NewTreeScanStateEmitter(conf, engine.GetLogger(), notif)
	require.NoError(t, err)
	t.Cleanup(emitter.Dispose)

	// Mark the Code product scan as completed so that info nodes are rendered.
	emitter.Emit(scanstates.StateSnapshot{
		ProductScanStates: map[types.FilePath]map[product.Product]bool{
			types.PathKey(folderPath): {product.ProductCode: false},
		},
	})

	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return receivedPayload != nil
	}, 2*time.Second, 50*time.Millisecond)

	mu.Lock()
	treeView := receivedPayload.(types.TreeView)
	mu.Unlock()
	assert.Contains(t, treeView.TreeViewHtml, "Open and Ignored issues are disabled!",
		"global disabled IVO with no folder override must produce the disabled info message")
}

// TestFilterState_MultipleFolders_DifferingSeverity_SetsMixedAndRendersFilterMixed is an
// end-to-end test: when two open folders have different per-folder severity
// filters the toolbar button carries filter-mixed.
func TestFilterState_MultipleFolders_DifferingSeverity_SetsMixedAndRendersFilterMixed(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()

	folder1 := types.FilePath("/project-mixed-a")
	folder2 := types.FilePath("/project-mixed-b")
	workspaceutil.SetupWorkspace(t, engine, folder1, folder2)

	// Folder 1: critical ON; folder 2: critical OFF — they disagree on Critical.
	sf1 := types.NewSeverityFilter(true, true, true, true)
	sf2 := types.NewSeverityFilter(false, true, true, true)
	types.SetSeverityFilterForFolder(conf, folder1, &sf1)
	types.SetSeverityFilterForFolder(conf, folder2, &sf2)

	notif := notification.NewNotifier()
	var mu sync.Mutex
	var receivedPayload any
	notif.CreateListener(func(params any) {
		mu.Lock()
		defer mu.Unlock()
		receivedPayload = params
	})
	t.Cleanup(func() { notif.DisposeListener() })

	emitter, err := NewTreeScanStateEmitter(conf, engine.GetLogger(), notif)
	require.NoError(t, err)
	t.Cleanup(emitter.Dispose)

	emitter.Emit(scanstates.StateSnapshot{})

	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return receivedPayload != nil
	}, 2*time.Second, 50*time.Millisecond)

	mu.Lock()
	treeView := receivedPayload.(types.TreeView)
	mu.Unlock()
	assert.Contains(t, treeView.TreeViewHtml, "filter-mixed",
		"HTML should contain filter-mixed class when folders disagree on severity")
	assert.Contains(t, treeView.TreeViewHtml, "Open folders use different Critical severity filters",
		"mixed critical button should carry the expected tooltip text")
}

// TestFilterState_NoWorkspace_FallsBackToGlobal verifies the ws==nil fallback:
// filterState must return the global config values when there is no workspace.
func TestFilterState_NoWorkspace_FallsBackToGlobal(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()

	// Set a distinctive non-default global filter: only High enabled.
	conf.Set(configresolver.UserGlobalKey(types.SettingSeverityFilterCritical), false)
	conf.Set(configresolver.UserGlobalKey(types.SettingSeverityFilterHigh), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSeverityFilterMedium), false)
	conf.Set(configresolver.UserGlobalKey(types.SettingSeverityFilterLow), false)

	// No workspace is set up — GetWorkspace returns nil.
	notif := notification.NewNotifier()
	notif.CreateListener(func(params any) {})
	t.Cleanup(func() { notif.DisposeListener() })

	emitter, err := NewTreeScanStateEmitter(conf, engine.GetLogger(), notif)
	require.NoError(t, err)
	t.Cleanup(emitter.Dispose)

	ws := config.GetWorkspace(conf)
	fs := emitter.filterState(ws)

	assert.False(t, fs.SeverityFilter.Critical, "global fallback: Critical should be false")
	assert.True(t, fs.SeverityFilter.High, "global fallback: High should be true")
	assert.False(t, fs.SeverityFilter.Medium, "global fallback: Medium should be false")
	assert.False(t, fs.SeverityFilter.Low, "global fallback: Low should be false")
	assert.Equal(t, MixedSeverity{}, fs.MixedSeverity, "no workspace → no mixed severity")
}

// TestFilterState_FolderWithNilConfigReadOnly_IsSkipped verifies that a folder
// whose FolderConfigReadOnly() returns nil is silently skipped and does not panic.
// When all folders are skipped the global fallback is used.
func TestFilterState_FolderWithNilConfigReadOnly_IsSkipped(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()

	// Global: all OFF.
	conf.Set(configresolver.UserGlobalKey(types.SettingSeverityFilterCritical), false)
	conf.Set(configresolver.UserGlobalKey(types.SettingSeverityFilterHigh), false)
	conf.Set(configresolver.UserGlobalKey(types.SettingSeverityFilterMedium), false)
	conf.Set(configresolver.UserGlobalKey(types.SettingSeverityFilterLow), false)

	// SetupWorkspace with a valid folder so there IS a workspace (ws != nil), but
	// the folder itself will have a valid FolderConfigReadOnly. We then call
	// filterState with a manually-constructed workspace that has no folders
	// (simulating the "all folders skipped" case).
	workspaceutil.SetupWorkspace(t, engine, types.FilePath("/project-nil-fc"))

	notif := notification.NewNotifier()
	notif.CreateListener(func(params any) {})
	t.Cleanup(func() { notif.DisposeListener() })

	emitter, err := NewTreeScanStateEmitter(conf, engine.GetLogger(), notif)
	require.NoError(t, err)
	t.Cleanup(emitter.Dispose)

	// Call filterState with nil — the ws==nil path falls straight to global.
	fs := emitter.filterState(nil)

	assert.False(t, fs.SeverityFilter.Critical, "nil workspace → global fallback: Critical=false")
	assert.Equal(t, MixedSeverity{}, fs.MixedSeverity, "nil workspace → no mixed severity")
}

// TestFilterState_IVO_PinsSingleFolderBehavior pins the CURRENT (non-aggregated) IVO
// semantics: when folders disagree, filterState takes one folder's IVO wholesale rather
// than aggregating across folders (unlike severity, which detects "mixed"). Workspace.Folders()
// iterates a map, so *which* folder is picked is non-deterministic — the test therefore
// asserts the result is exactly one of the two folders' values, never an OR/AND aggregate.
// This test will deliberately fail when the follow-up IVO aggregation branch lands — that
// failure is intentional and the test should then be updated.
func TestFilterState_IVO_PinsSingleFolderBehavior(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()

	folder1 := types.FilePath("/project-ivo-first")
	folder2 := types.FilePath("/project-ivo-second")
	workspaceutil.SetupWorkspace(t, engine, folder1, folder2)

	// Opposite settings so aggregation is detectable: an OR-aggregate would yield
	// both-true, an AND-aggregate both-false. A single-folder pick yields exactly one.
	ivo1 := types.NewIssueViewOptions(true, false)
	ivo2 := types.NewIssueViewOptions(false, true)
	types.SetIssueViewOptionsForFolder(conf, folder1, &ivo1)
	types.SetIssueViewOptionsForFolder(conf, folder2, &ivo2)

	notif := notification.NewNotifier()
	notif.CreateListener(func(params any) {})
	t.Cleanup(func() { notif.DisposeListener() })

	emitter, err := NewTreeScanStateEmitter(conf, engine.GetLogger(), notif)
	require.NoError(t, err)
	t.Cleanup(emitter.Dispose)

	ws := config.GetWorkspace(conf)
	fs := emitter.filterState(ws)

	// Current behavior: exactly one folder's IVO is used wholesale (not aggregated).
	// Folder iteration order is non-deterministic, so accept either folder's value.
	got := fs.IssueViewOptions
	matchesOneFolder := got == ivo1 || got == ivo2
	assert.True(t, matchesOneFolder,
		"IVO should equal exactly one folder's value (no aggregation); got %+v", got)
}

// TestFilterState_AggregateSeverityFilters_UsesFilters0AsBaseline verifies the coupling:
// aggregateSeverityFilters uses filters[0] as the baseline, and MixedSeverity is only
// set where a subsequent filter disagrees with that baseline.
func TestFilterState_AggregateSeverityFilters_UsesFilters0AsBaseline(t *testing.T) {
	// All agree with filters[0]: no mixed.
	f0 := types.NewSeverityFilter(true, false, true, false)
	f1 := types.NewSeverityFilter(true, false, true, false)
	sev, mixed := aggregateSeverityFilters([]types.SeverityFilter{f0, f1})
	assert.Equal(t, f0, sev, "when all agree, filters[0] is returned verbatim")
	assert.Equal(t, MixedSeverity{}, mixed, "no disagreement → no mixed flags")

	// f1 disagrees on High and Low relative to filters[0].
	f2 := types.NewSeverityFilter(true, true, true, true) // High and Low differ from f0
	_, mixed2 := aggregateSeverityFilters([]types.SeverityFilter{f0, f2})
	assert.False(t, mixed2.Critical, "Critical agrees with baseline → not mixed")
	assert.True(t, mixed2.High, "High differs from baseline → mixed")
	assert.False(t, mixed2.Medium, "Medium agrees with baseline → not mixed")
	assert.True(t, mixed2.Low, "Low differs from baseline → mixed")
}
