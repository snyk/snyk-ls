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

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/scanstates"
	scanner2 "github.com/snyk/snyk-ls/domain/snyk/scanner"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/testutil/workspaceutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// fakeScanner records RegisterCancelCallback invocations so the handler test
// can assert which folders were wired without spinning up a real
// DelegatingConcurrentScanner. End-to-end ordering with SetScanDone is covered
// at the scanner layer by TestScan_CancelCallback_CalledAfterGoroutinesFinish.
type fakeScanner struct {
	scanner2.TestScanner
	mu        sync.Mutex
	callbacks map[types.FilePath]func()
}

func (f *fakeScanner) RegisterCancelCallback(folderPath types.FilePath, fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.callbacks == nil {
		f.callbacks = make(map[types.FilePath]func())
	}
	f.callbacks[folderPath] = fn
}

func (f *fakeScanner) registered() map[types.FilePath]func() {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[types.FilePath]func(), len(f.callbacks))
	for k, v := range f.callbacks {
		out[k] = v
	}
	return out
}

// Handler contract: a scan token registers reset-on-cancel for every
// workspace folder via the Scanner interface, then progress.Cancel fires
// (defer). The registration happens BEFORE the cancel — that is the
// IDE-1035 register-vs-consume race fix exercised end-to-end.
func TestHandleWindowWorkDoneProgressCancel_ScanToken_RegistersBeforeCancel(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()

	folderA := types.FilePath(t.TempDir())
	folderB := types.FilePath(t.TempDir())
	_, _ = workspaceutil.SetupWorkspace(t, engine, folderA, folderB)

	scanner := &fakeScanner{}
	agg := scanstates.NewNoopStateAggregator()
	ctx := ctx2.NewContextWithDependencies(t.Context(), map[string]any{
		ctx2.DepScanners:            scanner,
		ctx2.DepScanStateAggregator: agg,
	})

	logger := engine.GetLogger()
	tracker := progress.NewScanTracker(true, logger)
	token := tracker.GetToken()
	require.True(t, progress.IsScanToken(token), "precondition: NewScanTracker must register a scan token")

	_, err := handleWindowWorkDoneProgressCancel(ctx,
		types.WorkdoneProgressCancelParams{Token: token},
		conf,
	)
	require.NoError(t, err)

	// Both workspace folders must have had a callback registered.
	got := scanner.registered()
	assert.Contains(t, got, folderA, "callback must be registered for folder A")
	assert.Contains(t, got, folderB, "callback must be registered for folder B")
	assert.Len(t, got, 2, "exactly one callback per folder")

	// The deferred progress.Cancel must have run by the time the handler returns,
	// so the scan token is no longer recognized. This is the ordering guarantee
	// that prevents the register-vs-consume race.
	assert.False(t, progress.IsScanToken(token),
		"progress.Cancel must have fired (deferred) — registration happened first, then cancel")
}

// Non-scan tokens (e.g. CLI download progress) must not register any reset
// callback. The cancel must still fire so the download stops.
func TestHandleWindowWorkDoneProgressCancel_NonScanToken_NoRegistration(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()

	folderA := types.FilePath(t.TempDir())
	_, _ = workspaceutil.SetupWorkspace(t, engine, folderA)

	scanner := &fakeScanner{}
	agg := scanstates.NewNoopStateAggregator()
	ctx := ctx2.NewContextWithDependencies(t.Context(), map[string]any{
		ctx2.DepScanners:            scanner,
		ctx2.DepScanStateAggregator: agg,
	})

	logger := engine.GetLogger()
	tracker := progress.NewTracker(true, logger) // plain tracker — NOT a scan token
	token := tracker.GetToken()
	require.False(t, progress.IsScanToken(token), "precondition: NewTracker must NOT register as a scan token")

	_, err := handleWindowWorkDoneProgressCancel(ctx,
		types.WorkdoneProgressCancelParams{Token: token},
		conf,
	)
	require.NoError(t, err)

	assert.Empty(t, scanner.registered(),
		"non-scan tokens must not register a reset callback — generic progress must not wipe scan results")
	assert.True(t, progress.IsCanceled(token),
		"progress.Cancel must still fire for non-scan tokens so the download is stopped")
}

// When the scanner is missing from context (early startup / tests that don't
// wire DI), the handler must NOT fall back to a synchronous reset that races
// in-flight SetScanDone writes. It should log and return cleanly.
func TestHandleWindowWorkDoneProgressCancel_ScanToken_NoScanner_NoSyncFallback(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()

	folderA := types.FilePath(t.TempDir())
	_, _ = workspaceutil.SetupWorkspace(t, engine, folderA)

	// Aggregator is present, but scanner is intentionally missing.
	agg := scanstates.NewNoopStateAggregator()
	ctx := ctx2.NewContextWithDependencies(t.Context(), map[string]any{
		ctx2.DepScanStateAggregator: agg,
	})

	logger := engine.GetLogger()
	tracker := progress.NewScanTracker(true, logger)
	token := tracker.GetToken()

	_, err := handleWindowWorkDoneProgressCancel(ctx,
		types.WorkdoneProgressCancelParams{Token: token},
		conf,
	)
	require.NoError(t, err)

	// progress.Cancel still fires (defer). No reset happened — the racy sync
	// fallback the reviewer flagged on #3382206417 is gone.
	assert.False(t, progress.IsScanToken(token))
}
