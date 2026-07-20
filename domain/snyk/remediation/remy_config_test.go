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

package remediation

import (
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
)

// TestBuildRemyFixConfig_SelectsSastAgenticFlow is the regression guard for the
// fix-folder no-op bug: the fix workflow must be told to run the Snyk Code (SAST)
// agentic flow, mirroring the proven CLI invocation
// `snyk fix <dir> --agentic --sast --experimental --auto-approve`. Without an
// explicit product flow the workflow defaults to SCA, finds nothing, and returns
// no changes. An empty-string key must never be set — it is a no-op that selects
// no product flow.
func TestBuildRemyFixConfig_SelectsSastAgenticFlow(t *testing.T) {
	const contentRoot = "/work/repo-root"

	conf := buildRemyFixConfig(configuration.NewWithOpts(), contentRoot)

	assert.True(t, conf.GetBool("agentic"), "agentic must be enabled")
	assert.True(t, conf.GetBool("sast"), "sast must be enabled to select the Snyk Code agentic flow")
	assert.True(t, conf.GetBool("experimental"), "experimental must be enabled")
	assert.True(t, conf.GetBool("auto-approve"), "auto-approve must be enabled for non-interactive use")
	assert.True(t, conf.GetBool("quiet"), "quiet must be enabled")
	assert.Equal(t, []string{contentRoot}, conf.GetStringSlice(configuration.INPUT_DIRECTORY),
		"INPUT_DIRECTORY must be exactly the content root")
	assert.False(t, conf.IsSet(""), "no empty-string key may be set")
}
