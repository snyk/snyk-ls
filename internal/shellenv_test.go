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

package env

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// IDE2015-010..016: unit tests for the LoadShellEnvUnlessDisabled env-var contract.
func Test_LoadShellEnvUnlessDisabled_EnvVarContract(t *testing.T) {
	cases := []struct {
		id          string
		value       string
		setEnv      bool // false = unset the var entirely
		wantSkipped bool
	}{
		// ID IDE2015-016: unset → loader runs
		{"IDE2015-016", "", false, false},
		// ID IDE2015-010: empty string → loader runs (same as unset)
		{"IDE2015-010", "", true, false},
		// ID IDE2015-011: "0" → loader runs (explicit opt-in to legacy behavior)
		{"IDE2015-011", "0", true, false},
		// ID IDE2015-012: "false" → loader runs
		{"IDE2015-012", "false", true, false},
		// ID IDE2015-013: "1" → skipped
		{"IDE2015-013", "1", true, true},
		// ID IDE2015-014: "true" → skipped
		{"IDE2015-014", "true", true, true},
		// ID IDE2015-015: typo ("tru") → skipped (fail-safe: any unrecognized value disables the call)
		{"IDE2015-015", "tru", true, true},
	}

	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			if tc.setEnv {
				t.Setenv(DisableShellEnvLoadingEnvVar, tc.value)
			} else {
				// Ensure the var is truly unset even if a parent test set it.
				t.Setenv(DisableShellEnvLoadingEnvVar, "")
				os.Unsetenv(DisableShellEnvLoadingEnvVar)
			}

			// We call with empty args so that, when the loader DOES run, it is a
			// no-op (no custom config files, no working directory). We are only
			// asserting the return value here; the integration test in
			// infrastructure/cli/ asserts the subprocess behavior.
			skipped := LoadShellEnvUnlessDisabled(nil, "")
			assert.Equal(t, tc.wantSkipped, skipped, "env=%q setEnv=%v", tc.value, tc.setEnv)
		})
	}
}
