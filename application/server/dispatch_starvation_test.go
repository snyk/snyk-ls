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

// IDE-2181 — dispatch starvation.
//
// When the stored OAuth token is expired/revoked, the scanner's Init path enters
// a failing token-refresh storm. Historically initializedHandler ran that Init
// synchronously, so it held a jrpc2 dispatch worker for the whole storm (~60s in
// the field). With a saturated worker pool the later workspace/executeCommand that
// asks for the settings-configuration HTML was never dispatched until Init unblocked
// — even though rendering that HTML needs no auth and is fast.
//
// These tests inject a scanner whose Init blocks (a faithful stand-in for the
// failing-refresh storm) and pin the server worker pool to 1 so the starvation is
// deterministic regardless of host core count. They are RED before CP1 (config HTML
// starved / initialized blocks) and GREEN after (init runs in the background).

import (
	"context"
	"sync"
	"testing"
	"time"

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// blockingInitScanner embeds a TestScanner (for the full Scanner interface) and
// overrides Init so it blocks until released — simulating the failing startup
// token-refresh storm that occupies the initialized handler.
type blockingInitScanner struct {
	*scanner.TestScanner
	started   chan struct{} // closed when Init begins
	release   chan struct{} // close to let Init return
	startOnce sync.Once
}

func newBlockingInitScanner() *blockingInitScanner {
	return &blockingInitScanner{
		TestScanner: scanner.NewTestScanner(),
		started:     make(chan struct{}),
		release:     make(chan struct{}),
	}
}

func (s *blockingInitScanner) Init(_ context.Context) error {
	s.startOnce.Do(func() { close(s.started) })
	select {
	case <-s.release:
	case <-time.After(60 * time.Second): // safety net: a test must never hang forever
	}
	return nil
}

// configCommandBudget is comfortably under the plugin's ~33s command budget yet far
// above the real config-HTML render time (<100ms), so a RED run fails on starvation
// while a GREEN run passes with wide margin even on slow CI.
const configCommandBudget = 10 * time.Second

// Test_ConfigHTML_ServicedDuringFailingStartupRefresh is the acceptance/regression
// test for the primary IDE-2181 root cause: the settings-configuration HTML must be
// returned promptly even while a startup token refresh keeps failing.
func Test_ConfigHTML_ServicedDuringFailingStartupRefresh(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)

	sc := newBlockingInitScanner()
	// Release the blocked Init before setupServer's shutdown cleanup runs. t.Cleanup is
	// LIFO and setupServer registers its shutdown after this test body executes, so a
	// t.Cleanup(close) here would release Init only AFTER shutdown tore down the engine —
	// letting the background init goroutine run HandleFolders/ScanWorkspace against a
	// torn-down engine. Releasing via defer at the top of the body guarantees Init unblocks
	// before shutdown.
	defer close(sc.release)

	// Concurrency:1 => a single dispatch worker. This deterministically reproduces
	// the saturated-pool starvation from the ticket on any core count. Real DI gives
	// a real command service so the configuration command actually renders HTML.
	loc, _, _ := setupServer(t, engine, tokenService,
		WithRealDI(),
		WithScanner(sc),
		WithServerConcurrency(1),
	)

	disableAutoScan(t, engine.GetConfiguration())

	_, err := loc.Client.Call(t.Context(), "initialize", buildInitParams(t, 1))
	require.NoError(t, err)

	// Fire "initialized" without waiting for its response: pre-fix it blocks on the
	// failing refresh, so waiting here would deadlock the test.
	go func() {
		_, _ = loc.Client.Call(context.Background(), "initialized", types.InitializedParams{})
	}()

	// Ensure Init has begun (worker occupied pre-fix) before requesting the HTML,
	// so the outcome is a property of dispatch behavior, not request ordering.
	select {
	case <-sc.started:
	case <-time.After(configCommandBudget):
		t.Fatal("scanner Init never started")
	}

	type result struct {
		html string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, callErr := loc.Client.Call(context.Background(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
			Command:   types.WorkspaceConfigurationCommand,
			Arguments: []any{},
		})
		var html string
		if callErr == nil {
			callErr = resp.UnmarshalResult(&html)
		}
		done <- result{html: html, err: callErr}
	}()

	select {
	case r := <-done:
		require.NoError(t, r.err, "config HTML command should succeed")
		require.NotEmpty(t, r.html, "config HTML should not be empty")
	case <-time.After(configCommandBudget):
		t.Fatalf("settings-configuration HTML was not returned within %v — dispatch starved by the failing startup token refresh", configCommandBudget)
	}
}

// Test_InitializedHandler_ReturnsPromptly_AndSignalsAfterScannerReady covers the
// integration + ordering (D1) invariants: the initialized acknowledgement must
// return without waiting for the (blocked) scanner Init, and SettingIsLspInitialized
// must flip only once the background init actually completes.
func Test_InitializedHandler_ReturnsPromptly_AndSignalsAfterScannerReady(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()

	sc := newBlockingInitScanner()
	loc, _, _ := setupServer(t, engine, tokenService, WithRealDI(), WithScanner(sc))

	disableAutoScan(t, conf)

	_, err := loc.Client.Call(t.Context(), "initialize", buildInitParams(t, 1))
	require.NoError(t, err)

	start := time.Now()
	_, err = loc.Client.Call(t.Context(), "initialized", types.InitializedParams{})
	elapsed := time.Since(start)
	require.NoError(t, err)

	// The handler must not block on the failing/slow scanner Init.
	require.Less(t, elapsed, 2*time.Second,
		"initialized handler returned in %v; it must not wait for the scanner Init (dispatch starvation)", elapsed)

	// Ordering invariant D1: "initialized ⇒ scanner ready". While Init is still
	// blocked, the signal must NOT have fired yet.
	<-sc.started
	require.False(t, conf.GetBool(types.SettingIsLspInitialized),
		"SettingIsLspInitialized must stay false until the background scanner init completes")

	// Release Init; the signal must then fire.
	close(sc.release)
	require.Eventually(t, func() bool {
		return conf.GetBool(types.SettingIsLspInitialized)
	}, 5*time.Second, 10*time.Millisecond,
		"SettingIsLspInitialized must become true once the background scanner init completes")
}
