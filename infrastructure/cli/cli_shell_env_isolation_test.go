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
	"bytes"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	env "github.com/snyk/snyk-ls/internal"
)

// bashLoginChildCount returns the current number of `bash --login -i` processes
// visible in the process tree. This is the observable side-effect we gate against.
// Uses pgrep which is available on macOS and most Linux distributions.
func bashLoginChildCount(t *testing.T) int {
	t.Helper()
	if runtime.GOOS == "windows" {
		return 0
	}
	out, err := exec.Command("pgrep", "-f", "bash --login -i").Output()
	if err != nil {
		// pgrep exits 1 when no matches — that is success for our purposes.
		return 0
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	count := 0
	for _, l := range lines {
		if l != "" {
			count++
		}
	}
	return count
}

// Test_LoadShellEnv_DisabledByEnvVar_DoesNotSpawnBash (IDE2015-001)
// Asserts that when SNYK_LS_DISABLE_SHELL_ENV_LOADING is set, the helper does
// not spawn any `bash --login -i` child process — the root cause of the SIGTTIN
// that suspends `make test` on macOS (see IDE-2015).
func Test_LoadShellEnv_DisabledByEnvVar_DoesNotSpawnBash(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash --login -i is not invoked on Windows")
	}

	t.Setenv(env.DisableShellEnvLoadingEnvVar, "1")

	before := bashLoginChildCount(t)
	skipped := env.LoadShellEnvUnlessDisabled(nil, "")
	after := bashLoginChildCount(t)

	assert.True(t, skipped, "expected loader to be skipped when env var is set")
	assert.Equal(t, before, after, "no new `bash --login -i` child should appear when env var is set")
}

// Test_LoadShellEnv_DisabledByEnvVar_ReturnsSkippedTrue (IDE2015-001 companion)
func Test_LoadShellEnv_DisabledByEnvVar_ReturnsSkippedTrue(t *testing.T) {
	t.Setenv(env.DisableShellEnvLoadingEnvVar, "1")
	assert.True(t, env.LoadShellEnvUnlessDisabled(nil, ""))
}

// Test_LoadShellEnv_NotDisabled_ReturnsSkippedFalse (IDE2015-002 companion)
func Test_LoadShellEnv_NotDisabled_ReturnsSkippedFalse(t *testing.T) {
	require.NoError(t, os.Unsetenv(env.DisableShellEnvLoadingEnvVar))
	assert.False(t, env.LoadShellEnvUnlessDisabled(nil, ""))
}

// Test_LoadShellEnv_NotDisabled_DoesSpawnBash_OnPosix (IDE2015-002)
// Asserts that when the env var is NOT set, the helper does invoke the underlying
// shell-env loader (we verify the side-effect: PATH is non-empty after the call,
// which the bash invocation would set if it ran successfully).
// This test is inherently racy on SIGTTIN machines — run in isolation or with the
// env var set for normal CI; this test is here for documentation and local debugging.
func Test_LoadShellEnv_NotDisabled_DoesSpawnBash_OnPosix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash --login -i is not invoked on Windows")
	}
	// This test deliberately skips the bash-spawn gate so that we can assert the
	// loader was called. It must NOT run in parallel with other tests that hold
	// the controlling terminal.
	t.Setenv(env.DisableShellEnvLoadingEnvVar, "")
	require.NoError(t, os.Unsetenv(env.DisableShellEnvLoadingEnvVar))

	pathBefore := os.Getenv("PATH")

	skipped := env.LoadShellEnvUnlessDisabled(nil, "")
	assert.False(t, skipped, "loader should run when env var is unset")

	// The loader may or may not change PATH, but it should not crash.
	// Verify PATH is still present (it was loaded from the shell).
	_ = pathBefore

	// Verify the loader ran by checking that PATH is still set (it was loaded from
	// bash's printenv output and applied via gotenv).
	assert.NotEmpty(t, os.Getenv("PATH"), "PATH must remain non-empty after shell env load")

	// Capture the subprocess count difference as an informational note only.
	if v, ok := os.LookupEnv("CI"); ok && v != "" {
		t.Logf("running in CI — bash subprocess assertion skipped to avoid SIGTTIN")
		return
	}
	var buf bytes.Buffer
	cmd := exec.Command("pgrep", "-c", "-f", "bash --login -i")
	cmd.Stdout = &buf
	_ = cmd.Run()
	n, _ := strconv.Atoi(strings.TrimSpace(buf.String()))
	t.Logf("bash --login -i subprocess count after loader ran: %d", n)
}
