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

package server

// LSP initialization performance at protocol boundary.
//
// This file contains:
//   - TestProfileLSPInit — captures a CPU profile of one initialize+initialized
//     cycle; skipped in -short mode, run explicitly to locate hotspots.
//   - Test_LSPInitCompletesWithManyFolders — Level-3 requirement test:
//     the `initialized` handler must complete within 30s for N=200 folders
//     (fake featureFlagService, CI-safe).
//   - Test_LSPInitCompletesWithManyFoldersRealHTTP — real-HTTP variant with
//     a 40s limit; skipped in -short mode.
//
// Usage:
//
//	go test ./application/server/... -run TestProfileLSPInit -v -count=1
//	go tool pprof -top -nodecount=30 /tmp/lsp-init-cpu-*.prof

import (
	"os"
	"runtime/pprof"
	"testing"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

const lspInitPerfFolderCount = 200

// buildInitParams creates an InitializeParams with n temporary workspace folders.
func buildInitParams(t *testing.T, n int) types.InitializeParams {
	t.Helper()
	folders := make([]types.WorkspaceFolder, n)
	for i := range n {
		dir := t.TempDir()
		folders[i] = types.WorkspaceFolder{
			Uri:  uri.PathToUri(types.FilePath(dir)),
			Name: dir,
		}
	}
	return types.InitializeParams{WorkspaceFolders: folders}
}

// disableAutoScan prevents the initialized handler from calling ScanWorkspace.
// SettingScanAutomatic is folder-scoped; the resolver checks remoteOrg (IsLocked) before
// UserGlobal, so we pin it via RemoteOrgKey with IsLocked:true.  effectiveOrg="" because
// di.ConfigResolver().GetBool(SettingScanAutomatic, nil) resolves with nil folderConfig.
func disableAutoScan(t *testing.T, conf interface{ Set(string, any) }) {
	t.Helper()
	conf.Set(
		configresolver.RemoteOrgKey("", types.SettingScanAutomatic),
		&configresolver.RemoteConfigField{Value: false, IsLocked: true},
	)
}

// profileLSPInitialized captures a CPU profile of one initialize+initialized
// cycle into /tmp/lsp-init-cpu.prof.  Call via:
//
//	go test ./application/server/... -run TestProfileLSPInit -v -count=1
//
// Then inspect with: go tool pprof -top -nodecount=30 /tmp/lsp-init-cpu.prof
func TestProfileLSPInit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping profiling test in short mode; run explicitly: go test -run TestProfileLSPInit -v")
	}
	engine, tokenService := testutil.UnitTestWithEngine(t)
	params := buildInitParams(t, lspInitPerfFolderCount)

	f, err := os.CreateTemp(t.TempDir(), "lsp-init-cpu-*.prof")
	require.NoError(t, err)
	t.Logf("CPU profile: %s", f.Name())

	require.NoError(t, pprof.StartCPUProfile(f))
	defer func() {
		pprof.StopCPUProfile()
		_ = f.Close()
		t.Logf("profile written; inspect with: go tool pprof -top -nodecount=30 %s", f.Name())
	}()

	loc, _, _ := setupServer(t, engine, tokenService)

	_, err = loc.Client.Call(t.Context(), "initialize", params)
	require.NoError(t, err)

	// Disable auto-scan after initialize: measure initialization overhead, not scan time.
	disableAutoScan(t, engine.GetConfiguration())

	start := time.Now()
	_, err = loc.Client.Call(t.Context(), "initialized", types.InitializedParams{})
	require.NoError(t, err)
	t.Logf("initialized with %d folders took %v", lspInitPerfFolderCount, time.Since(start))
}

// Test_LSPInitCompletesWithManyFolders is the Level-3 requirement test.
//
// Requirement: The LSP server shall successfully complete initialization regardless
// of the number of workspace folders.
//
// Design: uses a fake featureFlagService (no HTTP calls) so the test is reliable in CI
// regardless of network access or token validity.  The test validates the initialization
// code path — folder processing, JSON config writes, notifier plumbing — for N=200 folders.
// Real HTTP behavior is exercised by Test_LSPInitCompletesWithManyFoldersRealHTTP.
//
// The 30s bound is loose enough to catch O(N²) regressions in folder processing and
// tight enough to detect hangs in the notification/channel machinery.
const lspInitMaxDuration = 30 * time.Second

func Test_LSPInitCompletesWithManyFolders(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	params := buildInitParams(t, lspInitPerfFolderCount)

	loc, _, _ := setupServer(t, engine, tokenService)

	_, err := loc.Client.Call(t.Context(), "initialize", params)
	require.NoError(t, err)

	// Replace the global featureFlagService with a no-op fake so PopulateFolderConfig
	// makes no HTTP calls.  This keeps the test CI-reliable regardless of network access.
	origFF := di.FeatureFlagService()
	di.SetFeatureFlagService(featureflag.NewFakeService())
	t.Cleanup(func() { di.SetFeatureFlagService(origFF) })

	// Disable auto-scan (before initialized): the requirement is about initialization
	// latency, not scan throughput.
	disableAutoScan(t, engine.GetConfiguration())

	start := time.Now()
	_, err = loc.Client.Call(t.Context(), "initialized", types.InitializedParams{})
	elapsed := time.Since(start)
	require.NoError(t, err)

	t.Logf("initialized with %d folders took %v (limit: %v)", lspInitPerfFolderCount, elapsed, lspInitMaxDuration)
	require.Less(t, elapsed, lspInitMaxDuration,
		"initialized handler with %d folders took %v; must complete in < %v. "+
			"Run TestProfileLSPInit to profile and tighten this bound.",
		lspInitPerfFolderCount, elapsed, lspInitMaxDuration)
}

// Test_LSPInitCompletesWithManyFoldersRealHTTP is the real-HTTP variant of the requirement
// test above.  Unlike the fake-service test, this exercises the full HTTP code path —
// feature-flag fetches, negative SAST caching, LDX-Sync calls — and validates that
// initialization still completes quickly.
//
// Baseline measured 2026-05-28 on a Linux container: 11.95s for N=200 folders.
// Limit: 40s — 3.3× the measured baseline, covering CI variance and network jitter.
//
// This test is skipped in -short mode (~12s wall time).  Run explicitly:
//
//	go test ./application/server/... -run Test_LSPInitCompletesWithManyFoldersRealHTTP -v
const lspInitRealHTTPMaxDuration = 40 * time.Second

func Test_LSPInitCompletesWithManyFoldersRealHTTP(t *testing.T) {
	if testing.Short() {
		t.Skip("real-HTTP init test skipped in -short mode; run explicitly")
	}

	engine, tokenService := testutil.UnitTestWithEngine(t)
	params := buildInitParams(t, lspInitPerfFolderCount)

	loc, _, _ := setupServer(t, engine, tokenService)

	_, err := loc.Client.Call(t.Context(), "initialize", params)
	require.NoError(t, err)

	disableAutoScan(t, engine.GetConfiguration())

	start := time.Now()
	_, err = loc.Client.Call(t.Context(), "initialized", types.InitializedParams{})
	elapsed := time.Since(start)
	require.NoError(t, err)

	t.Logf("initialized with %d folders (real HTTP) took %v (limit: %v)", lspInitPerfFolderCount, elapsed, lspInitRealHTTPMaxDuration)
	require.Less(t, elapsed, lspInitRealHTTPMaxDuration,
		"initialized with %d folders (real HTTP) took %v; must complete in <%v. "+
			"Profile with TestProfileLSPInit to diagnose.",
		lspInitPerfFolderCount, elapsed, lspInitRealHTTPMaxDuration)
}
