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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// TestWithAPIEndpoint_IsolatesPerEngine verifies that WithAPIEndpoint sets the
// API endpoint directly on the per-server configuration object rather than via
// a process-global os.Setenv. Two engines created with different endpoints must
// each report the endpoint that was requested for them, independently of the
// order in which they are set up.
//
// This is the acceptance test for the fix to the "non-deterministic test env"
// bug: the old sync.Once+os.Setenv approach made the first parallel test's
// endpoint win for the whole process, silently giving the wrong endpoint to
// every subsequent server that requested a different one.
//
// Run as: go test -race ./application/server/... -run TestWithAPIEndpoint -v
func TestWithAPIEndpoint_IsolatesPerEngine(t *testing.T) {
	t.Parallel()

	const endpointA = "https://api.snyk.io"
	const endpointB = "https://api.eu.snyk.io"

	// Set up engine A with endpoint A.
	engineA, tokenServiceA := testutil.UnitTestWithEngine(t)
	loc, _, _ := setupServer(t, engineA, tokenServiceA, WithAPIEndpoint(endpointA))
	_ = loc
	gotA := types.GetGlobalString(engineA.GetConfiguration(), types.SettingApiEndpoint)
	require.Equal(t, endpointA, gotA, "engine A must have endpoint A")

	// Set up engine B with endpoint B — independently of engine A.
	engineB, tokenServiceB := testutil.UnitTestWithEngine(t)
	loc, _, _ = setupServer(t, engineB, tokenServiceB, WithAPIEndpoint(endpointB))
	_ = loc
	gotB := types.GetGlobalString(engineB.GetConfiguration(), types.SettingApiEndpoint)
	assert.Equal(t, endpointB, gotB,
		"engine B must have endpoint B regardless of the order in which A and B are set up; "+
			"if this fails, the endpoint is leaking through a process-global mechanism (os.Setenv/sync.Once)")
}

// TestWithAPIEndpoint_EmptyIsNoOp verifies that passing an empty string to
// WithAPIEndpoint does not overwrite whatever the engine configuration already
// holds (mirrors the nil-safe behavior of the previous env-var code path in
// setupServer, which skipped UpdateApiEndpointsOnConfig when SNYK_API=="").
func TestWithAPIEndpoint_EmptyIsNoOp(t *testing.T) {
	t.Parallel()

	engine, tokenService := testutil.UnitTestWithEngine(t)

	// Pre-set an endpoint directly on the config before calling setupServer.
	const presetEndpoint = "https://api.snyk.io"
	config.UpdateApiEndpointsOnConfig(engine.GetConfiguration(), presetEndpoint)

	// WithAPIEndpoint("") must not overwrite the preset.
	loc, _, _ := setupServer(t, engine, tokenService, WithAPIEndpoint(""))
	_ = loc

	got := types.GetGlobalString(engine.GetConfiguration(), types.SettingApiEndpoint)
	assert.Equal(t, presetEndpoint, got, "empty WithAPIEndpoint must not overwrite existing config")
}
