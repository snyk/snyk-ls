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

// Tests for background-init goroutine lifecycle.
//
// The blocking scanner Init + folder handling + first scan run in a background
// goroutine so the initialized handler returns promptly and does not hold a
// dispatch worker. That async move introduced two lifecycle gaps these tests
// exercise:
//
//   1. The goroutine ran with no panic recovery. The same work previously ran inside
//      the handler call stack, which withContext wraps with recover(); a panic there
//      now escapes an unrecovered goroutine and the Go runtime terminates the whole
//      server.
//
//   2. The goroutine ran on an uncancellable context.Background() and `shutdown` neither
//      canceled nor awaited it. If the IDE closes during the (up to ~60s) failing-refresh
//      init window, shutdown disposes the notifier/tree-emitter/timers while the goroutine
//      is still mid-init, then the goroutine proceeds into HandleFolders/ScanWorkspace
//      against disposed state → use-after-dispose.

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

// lifecycleScanner records the context handed to Init and blocks in Init until that
// context is canceled (or an explicit release / safety-net timeout). It is a faithful
// stand-in for a scanner whose startup token refresh keeps failing: Init stays in flight
// until something cancels it.
type lifecycleScanner struct {
	*scanner.TestScanner
	initStarted chan struct{}
	release     chan struct{}
	startOnce   sync.Once

	mu           sync.Mutex
	initCtx      context.Context
	initReturned bool
}

func newLifecycleScanner() *lifecycleScanner {
	return &lifecycleScanner{
		TestScanner: scanner.NewTestScanner(),
		initStarted: make(chan struct{}),
		release:     make(chan struct{}),
	}
}

func (s *lifecycleScanner) Init(ctx context.Context) error {
	s.mu.Lock()
	s.initCtx = ctx
	s.mu.Unlock()
	s.startOnce.Do(func() { close(s.initStarted) })

	select {
	case <-ctx.Done():
	case <-s.release:
	case <-time.After(60 * time.Second): // safety net: a test must never hang forever
	}

	s.mu.Lock()
	s.initReturned = true
	s.mu.Unlock()
	return ctx.Err()
}

func (s *lifecycleScanner) getInitReturned() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.initReturned
}

func (s *lifecycleScanner) getInitCtx() context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.initCtx
}

// Test_Shutdown_CancelsAndAwaitsBackgroundInit verifies that shutdown cancels the
// background init context and waits for the goroutine to finish BEFORE it disposes
// the notifier/tree-emitter/timers. The goroutine must run on a cancellable context
// that shutdown cancels; Init must observe the cancellation and return before
// shutdown proceeds to tear down shared state.
func Test_Shutdown_CancelsAndAwaitsBackgroundInit(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()

	sc := newLifecycleScanner()
	// Release Init at body exit as a backstop so a RED run (where cancellation never
	// happens) does not leak a goroutine blocked on the 60s safety net.
	defer close(sc.release)

	loc, _, _ := setupServer(t, engine, tokenService, WithRealDI(), WithScanner(sc))
	disableAutoScan(t, conf)

	_, err := loc.Client.Call(t.Context(), "initialize", buildInitParams(t, 1))
	require.NoError(t, err)
	_, err = loc.Client.Call(t.Context(), "initialized", types.InitializedParams{})
	require.NoError(t, err)

	// Wait until the background goroutine is mid-init (Init started, still blocked).
	select {
	case <-sc.initStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("scanner Init never started")
	}
	require.False(t, sc.getInitReturned(),
		"precondition: the background scanner Init should still be blocked mid-init before shutdown")

	// Invoke shutdown while the background init is in flight.
	_, err = loc.Client.Call(t.Context(), "shutdown", nil)
	require.NoError(t, err)

	// Await: by the time shutdown returns, the goroutine must have finished, i.e. Init
	// observed cancellation and returned. If shutdown does not await, Init is still
	// blocked here and this fails.
	require.True(t, sc.getInitReturned(),
		"shutdown must cancel AND await the background init before disposing shared state; "+
			"Init had not returned when shutdown returned")

	// Cancel: the context handed to Init must be a cancellable one that shutdown
	// cancels — not context.Background().
	initCtx := sc.getInitCtx()
	require.NotNil(t, initCtx)
	require.Error(t, initCtx.Err(),
		"the background init must run on a cancellable context that shutdown cancels, not context.Background()")
}

// panicInitScanner panics inside Init to verify that a panic in the background init
// goroutine is recovered, the server survives, and the readiness signal still fires.
type panicInitScanner struct {
	*scanner.TestScanner
}

func (s *panicInitScanner) Init(_ context.Context) error {
	panic("simulated panic in background scanner init")
}

// Test_BackgroundInit_PanicRecovered_ServerSurvives_SignalFires verifies that a panic
// inside the background init goroutine is recovered, the readiness signal still fires
// (so WaitForLspInitialized waiters are released), and the server continues serving
// requests.
func Test_BackgroundInit_PanicRecovered_ServerSurvives_SignalFires(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	types.NewLspInitializedChannel(conf)

	sc := &panicInitScanner{TestScanner: scanner.NewTestScanner()}
	loc, _, _ := setupServer(t, engine, tokenService, WithRealDI(), WithScanner(sc))
	disableAutoScan(t, conf)

	_, err := loc.Client.Call(t.Context(), "initialize", buildInitParams(t, 1))
	require.NoError(t, err)
	_, err = loc.Client.Call(t.Context(), "initialized", types.InitializedParams{})
	require.NoError(t, err)

	// The readiness signal must fire even though the background init goroutine panicked.
	require.Eventually(t, func() bool {
		return conf.GetBool(types.SettingIsLspInitialized)
	}, 5*time.Second, 10*time.Millisecond,
		"readiness signal must still fire when the background init goroutine panics (recover must fire the signal)")

	// The server must still be alive and serving requests after the recovered panic.
	resp, err := loc.Client.Call(t.Context(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
		Command:   types.WorkspaceConfigurationCommand,
		Arguments: []any{},
	})
	require.NoError(t, err, "server must survive a recovered background-init panic and keep serving requests")
	var html string
	require.NoError(t, resp.UnmarshalResult(&html))
	require.NotEmpty(t, html)
}
