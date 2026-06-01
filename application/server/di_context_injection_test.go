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
	"context"
	"testing"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/handler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	er "github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// diTestScanPersister is a pointer-type stub so pointer-identity assertions
// (assert.Same) can distinguish the injected instance from any other NopScanPersister.
type diTestScanPersister struct {
	persistence.NopScanPersister
}

// diTestHoverService is a minimal hover.Service stub used to verify that
// withContext injects the deps-provided service, not the di package global.
type diTestHoverService struct {
	hover.Service
}

func (s *diTestHoverService) GetHover(_ types.FilePath, _ types.Position) hover.Result {
	return hover.Result{}
}

func (s *diTestHoverService) ClearAllHovers() {}

func (s *diTestHoverService) Channel() chan hover.DocumentHovers {
	return make(chan hover.DocumentHovers, 1)
}

// Test_withContext_injectsHoverService_isolatedFromGlobal proves that
// withContext injects the HoverService from the deps struct into the handler
// context, and that the injected value is the deps-provided instance — NOT
// the di.HoverService() package global.
//
// This is the key regression guard for IDE-1898: if withContext stops injecting
// HoverService, or a handler reverts to calling di.HoverService() directly,
// the two sentinels will differ and the assertions will fail.
func Test_withContext_injectsHoverService_isolatedFromGlobal(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()

	globalSentinel := &diTestHoverService{}
	contextSentinel := &diTestHoverService{}

	// Set the di package-level global to globalSentinel. Use the returned deps
	// as a base so all mandatory fields (e.g. ConfigResolver) are populated.
	baseDeps := di.TestInit(t, engine, tokenService, &di.Dependencies{
		HoverService: globalSentinel,
	})

	// Override only HoverService — withContext must inject contextSentinel, not
	// the globalSentinel that was passed to TestInit above.
	deps := baseDeps
	deps.HoverService = contextSentinel

	var gotService hover.Service
	wrapped := withContext(handler.New(func(ctx context.Context, _ *jrpc2.Request) (any, error) {
		gotService, _ = hoverServiceFromContext(ctx)
		return nil, nil
	}), logger, conf, engine, deps, nil)

	_, err := wrapped(t.Context(), nil)
	require.NoError(t, err)

	gotSentinel, ok := gotService.(*diTestHoverService)
	require.True(t, ok, "expected *diTestHoverService from context")
	assert.True(t, gotSentinel == contextSentinel,
		"withContext must inject the deps.HoverService into context, not read di.HoverService() global")
	assert.True(t, gotSentinel != globalSentinel,
		"handler must not use the di.HoverService() global")
}

// Test_withContext_injectsNewHandlerDependencies verifies that withContext
// injects the following di.Dependencies fields into the handler context:
// HoverService, ScanPersister, ErrorReporter.
//
// These are fields added in IDE-1898. AuthenticationService injection is
// already covered by TestWithContext_InjectsAuthenticationService in server_test.go.
func Test_withContext_injectsNewHandlerDependencies(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()

	scanPersister := &diTestScanPersister{}
	sentinel := &diTestHoverService{}
	errReporter := er.NewTestErrorReporter(engine)

	// Prime global DI state (satisfies validateMandatoryDeps inside withContext),
	// then override the three fields under test on the returned struct copy so the
	// test proves context injection uses the deps struct, not the di package globals.
	deps := di.TestInit(t, engine, tokenService, nil)
	deps.HoverService = sentinel
	deps.ScanPersister = scanPersister
	deps.ErrorReporter = errReporter

	var (
		gotHoverService  hover.Service
		gotScanPersister persistence.ScanSnapshotPersister
		gotErrorReporter er.ErrorReporter
	)

	wrapped := withContext(handler.New(func(ctx context.Context, _ *jrpc2.Request) (any, error) {
		ctxDeps, ok := ctx2.DependenciesFromContext(ctx)
		require.True(t, ok, "expected deps map in context")
		gotHoverService, _ = ctxDeps[ctx2.DepHoverService].(hover.Service)
		gotScanPersister, _ = ctxDeps[ctx2.DepScanPersister].(persistence.ScanSnapshotPersister)
		gotErrorReporter, _ = ctxDeps[ctx2.DepErrorReporter].(er.ErrorReporter)
		return nil, nil
	}), logger, conf, engine, deps, nil)

	_, err := wrapped(t.Context(), nil)
	require.NoError(t, err)

	assert.Same(t, sentinel, gotHoverService,
		"HoverService must be the exact instance injected into context")
	assert.Same(t, scanPersister, gotScanPersister,
		"ScanPersister must be the exact instance injected into context")
	assert.Same(t, errReporter, gotErrorReporter,
		"ErrorReporter must be the exact instance injected into context")
}
