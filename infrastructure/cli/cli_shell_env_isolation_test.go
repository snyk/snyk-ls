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

package cli_test

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	env "github.com/snyk/snyk-ls/internal"
)

// bashLoginChildCount returns the current number of `bash --login -i` processes
// visible in the process tree.
func bashLoginChildCount(t *testing.T) int {
	t.Helper()
	if runtime.GOOS == "windows" {
		return 0
	}
	out, err := exec.Command("pgrep", "-f", "bash --login -i").Output()
	if err != nil {
		return 0 // pgrep exits 1 when no matches
	}
	count := 0
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l != "" {
			count++
		}
	}
	return count
}

// Test_LoadShellEnv_DisabledByEnvVar_DoesNotSpawnBash (IDE2015-001)
// Asserts that when SNYK_LS_DISABLE_SHELL_ENV_LOADING is set, the helper does
// not spawn any `bash --login -i` child process — the root cause of the SIGTTIN
// that suspends `make test` on macOS (IDE-2015).
func Test_LoadShellEnv_DisabledByEnvVar_DoesNotSpawnBash(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash --login -i is not invoked on Windows")
	}

	t.Setenv(env.DisableShellEnvLoadingEnvVar, "1")

	before := bashLoginChildCount(t)
	skipped := env.LoadShellEnvUnlessDisabled(nil, "")
	after := bashLoginChildCount(t)

	require.True(t, skipped, "expected loader to be skipped when env var is set")
	assert.Equal(t, before, after, "no new `bash --login -i` child should appear when env var is set")
}
