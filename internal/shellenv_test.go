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
	"testing"

	"github.com/stretchr/testify/assert"
)

// IDE2015-013..015: unit tests for the LoadShellEnvUnlessDisabled skip cases.
//
// Only the disabled (skipped=true) paths are tested here. The enabled path
// (skipped=false) invokes envvars.LoadConfiguredEnvironment, which spawns
// `bash --login -i` — the exact TTY-seizure bug this package fixes (IDE-2015).
// Proving that "1"/"true"/unrecognized values return true is sufficient; the
// switch arm for "", "0", "false" is verified by reading the code and by the
// integration test Test_LoadShellEnv_DisabledByEnvVar_DoesNotSpawnBash in
// infrastructure/cli.
func Test_LoadShellEnvUnlessDisabled_SkipCases(t *testing.T) {
	cases := []struct {
		id    string
		value string
	}{
		// IDE2015-013: "1" -> skipped
		{"IDE2015-013", "1"},
		// IDE2015-014: "true" -> skipped
		{"IDE2015-014", "true"},
		// IDE2015-015: typo ("tru") -> skipped (fail-safe: unrecognized value disables)
		{"IDE2015-015", "tru"},
	}

	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			t.Setenv(DisableShellEnvLoadingEnvVar, tc.value)
			assert.True(t, LoadShellEnvUnlessDisabled(nil, ""), "env=%q must skip bash spawn", tc.value)
		})
	}
}
