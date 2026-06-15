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

// INTEG-110 (IDE-2036): Two-server per-server cancel isolation via progress.Tracker.
// Canceling a progress token on server A must not affect server B's tasks.

import (
	"context"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/di"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/testutil"
)

// TestTwoServerCancelIsolation_ViaTracker (INTEG-110) verifies that when two
// servers own separate *progress.Tracker instances, canceling a token on one
// Tracker does NOT affect the other Tracker's tasks.
func TestTwoServerCancelIsolation_ViaTracker(t *testing.T) {
	t.Parallel()

	logger := zerolog.Nop()

	engineA, tokenServiceA := testutil.UnitTestWithEngine(t)
	engineB, tokenServiceB := testutil.UnitTestWithEngine(t)

	ownerA := progress.NewTracker(&logger)
	ownerB := progress.NewTracker(&logger)

	depsA := di.TestInit(t, engineA, tokenServiceA, &di.Dependencies{ProgressTracker: ownerA})
	depsB := di.TestInit(t, engineB, tokenServiceB, &di.Dependencies{ProgressTracker: ownerB})

	require.Equal(t, ownerA, depsA.ProgressTracker, "depsA.ProgressTracker must be ownerA")
	require.Equal(t, ownerB, depsB.ProgressTracker, "depsB.ProgressTracker must be ownerB")

	// Create a task on each owner.
	taskA := depsA.ProgressTracker.New(true)
	taskB := depsB.ProgressTracker.New(true)

	tokenA := taskA.GetToken()
	tokenB := taskB.GetToken()

	// Before cancellation: both active.
	assert.False(t, depsA.ProgressTracker.IsCanceled(tokenA), "taskA should not be canceled initially")
	assert.False(t, depsB.ProgressTracker.IsCanceled(tokenB), "taskB should not be canceled initially")

	// Cancel A via its owner.
	depsA.ProgressTracker.Cancel(tokenA)

	assert.True(t, depsA.ProgressTracker.IsCanceled(tokenA), "taskA should be canceled after Cancel")
	assert.False(t, depsB.ProgressTracker.IsCanceled(tokenB), "taskB on ownerB must NOT be affected by canceling ownerA's task")

	// Drain cancel channel.
	select {
	case <-taskA.GetCancelChannel():
	case <-time.After(time.Second):
		t.Fatal("expected cancel signal on taskA")
	}
}

// TestProgressTrackerInjectedIntoContext verifies that the per-server
// *progress.Tracker is retrievable from the request context via
// mustProgressTrackerFromContext (composition-root wiring test).
func TestProgressTrackerInjectedIntoContext(t *testing.T) {
	t.Parallel()

	logger := zerolog.Nop()
	engine, tokenService := testutil.UnitTestWithEngine(t)
	owner := progress.NewTracker(&logger)

	deps := di.TestInit(t, engine, tokenService, &di.Dependencies{ProgressTracker: owner})

	// Build the context dep map the same way withContext does.
	ctxDeps := make(map[string]any)
	injectCoreServicesIntoMap(ctxDeps, deps)
	injectScanServicesIntoMap(ctxDeps, deps)

	ctx := ctx2.NewContextWithDependencies(context.Background(), ctxDeps)

	// The Tracker retrieved from context must be exactly the one we injected.
	got := mustProgressTrackerFromContext(ctx)
	require.Equal(t, owner, got, "mustProgressTrackerFromContext must return the injected Tracker")
}
