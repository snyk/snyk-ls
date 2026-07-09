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

// IDE-2181 — readiness-signal safety net.
//
// The LSP readiness signal (SettingIsLspInitialized + SignalLspInitialized) is
// normally fired at the END of the background scanner-init goroutine that
// initializedHandler launches, so scanner-readiness waiters block until real
// init completes (invariant D1). But every dependency resolution that runs
// BEFORE that goroutine launches — mustConfigResolverFromContext,
// mustNotifierFromContext, mustLearnServiceFromContext, mustScannerFromContext,
// … — panics on a missing dep. jrpc2 (and withContext) recover such a handler
// panic and keep the server alive, but the background goroutine is never
// reached, so without a safety net the signal never fires and any goroutine
// parked in WaitForLspInitialized (e.g. the outbound-notification dispatch in
// notification.go) blocks forever.
//
// This test drives initializedHandler down a dependency-resolution panic that
// happens before the goroutine launches and asserts that a WaitForLspInitialized
// caller is still released (the handler-level safety net fires the signal on
// exit). It is RED before the safety net (waiter stranded) and GREEN after.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/di"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_initializedHandler_FiresSignalWhenDepResolutionPanicsBeforeGoroutineLaunch(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()

	// The server wires the init channel at startup; WaitForLspInitialized blocks on it.
	types.NewLspInitializedChannel(conf)

	// Build the request context exactly as withContext does, then drop the Scanner so
	// mustScannerFromContext panics — a dependency resolution that runs BEFORE the
	// background scanner-init goroutine (which normally fires the readiness signal) is
	// launched.
	deps := di.TestInit(t, engine, tokenService, nil)
	logger := engine.GetLogger()
	ctxDeps := map[string]any{
		ctx2.DepConfiguration: conf,
		ctx2.DepEngine:        engine,
	}
	injectCoreServicesIntoMap(ctxDeps, deps)
	injectScanServicesIntoMap(ctxDeps, deps)
	delete(ctxDeps, ctx2.DepScanners)

	ctx := ctx2.NewContextWithLogger(context.Background(), logger)
	ctx = ctx2.NewContextWithDependencies(ctx, ctxDeps)

	// A goroutine parked in WaitForLspInitialized (a faithful stand-in for the
	// outbound-notification dispatch) must be released even though the handler panics
	// before the goroutine that normally fires the signal is launched.
	waiterReturned := make(chan struct{})
	go func() {
		types.WaitForLspInitialized(conf)
		close(waiterReturned)
	}()

	h := initializedHandler(conf, engine, nil)

	// Invoke the handler and recover the missing-dep panic, exactly as jrpc2/withContext
	// do in production — the server must survive it.
	recovered := make(chan any, 1)
	go func() {
		defer func() { recovered <- recover() }()
		_, _ = h(ctx, &jrpc2.Request{})
	}()

	select {
	case r := <-recovered:
		require.NotNil(t, r, "handler must panic on the missing Scanner dependency (drives the pre-goroutine path)")
		require.Contains(t, fmt.Sprintf("%v", r), "Scanner missing from context",
			"test must drive the dependency-resolution panic path, not some other failure")
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not return")
	}

	select {
	case <-waiterReturned:
		// Success: the handler-level safety net fired the readiness signal during panic
		// unwind, so the parked waiter was released.
	case <-time.After(2 * time.Second):
		t.Fatal("WaitForLspInitialized caller was stranded: the readiness signal never fired " +
			"after a dependency-resolution panic before the background goroutine launched")
	}
}
