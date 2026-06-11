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

// TestScanContextCanceledOnShutdown (IDE-2036-INTEG-004) verifies that the
// context passed to ScanWorkspace by initializedHandler is canceled when the
// shutdown handler runs.
//
// Run with:
//
//	go test ./application/server/... -run TestScanContextCanceledOnShutdown -v -count=1

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// contextCapturingWorkspace wraps a real types.Workspace and records the
// context that ScanWorkspace was called with, unblocking a channel so the
// test can synchronize without polling.
type contextCapturingWorkspace struct {
	types.Workspace // embed the real workspace for all other method calls

	mu      sync.Mutex
	scanCtx context.Context
	called  chan struct{}
}

func newContextCapturingWorkspace(delegate types.Workspace) *contextCapturingWorkspace {
	return &contextCapturingWorkspace{
		Workspace: delegate,
		called:    make(chan struct{}, 1),
	}
}

func (w *contextCapturingWorkspace) ScanWorkspace(ctx context.Context) {
	w.mu.Lock()
	w.scanCtx = ctx
	w.mu.Unlock()
	select {
	case w.called <- struct{}{}:
	default:
	}
	// Do not forward to the real workspace — we do not want real scans in this test.
}

func (w *contextCapturingWorkspace) capturedCtx() context.Context {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.scanCtx
}

func TestScanContextCanceledOnShutdown(t *testing.T) {
	// Not parallel: injects a workspace into the configuration, which modifies
	// engine-global state. Run sequentially so it does not interfere with other tests.

	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()

	// Enable automatic scanning (the default, but pin it explicitly so the test
	// is not sensitive to the default changing).
	conf.Set(
		configresolver.RemoteOrgKey("", types.SettingScanAutomatic),
		&configresolver.RemoteConfigField{Value: true, IsLocked: true},
	)

	// Setup the server using the standard test helper. This creates and registers
	// a real workspace via di.TestInit / config.SetWorkspace.
	loc, _, _ := setupServer(t, engine, tokenService)

	// Wrap the real workspace so we can capture the scan context.
	realWs := config.GetWorkspace(conf)
	require.NotNil(t, realWs, "workspace must be set after setupServer")
	capturingWs := newContextCapturingWorkspace(realWs)
	config.SetWorkspace(conf, capturingWs)

	// Run the LSP initialization handshake to trigger initializedHandler.
	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	require.NoError(t, err)

	_, err = loc.Client.Call(t.Context(), "initialized", nil)
	require.NoError(t, err)

	// Wait for ScanWorkspace to be called (initialized handler triggers it
	// asynchronously; give it a generous timeout).
	select {
	case <-capturingWs.called:
		// good — ScanWorkspace was called
	case <-time.After(10 * time.Second):
		t.Fatal("ScanWorkspace was not called within 10s after initialized")
	}

	scanCtx := capturingWs.capturedCtx()
	require.NotNil(t, scanCtx, "ScanWorkspace must have been called with a non-nil context")

	// Before shutdown: the scan context must NOT be canceled yet.
	assert.NoError(t, scanCtx.Err(), "scan context must be live before shutdown")

	// Trigger shutdown — this should cancel the scan context.
	_, err = loc.Client.Call(t.Context(), "shutdown", nil)
	require.NoError(t, err)

	// After shutdown: the scan context must be canceled so that in-flight scan
	// goroutines can exit (preventing Windows temp-dir cleanup races [IDE-2036]).
	assert.Eventually(t, func() bool {
		return scanCtx.Err() != nil
	}, 3*time.Second, time.Millisecond,
		"scan context must be canceled after shutdown (currently uses context.Background() which never cancels)")
}
