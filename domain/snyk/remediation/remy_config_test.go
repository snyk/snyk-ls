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

	"github.com/snyk/snyk-ls/internal/types"
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
	assert.False(t, conf.IsSet("quiet"), "quiet must not be set (not a valid config key)")
	assert.Equal(t, []string{contentRoot}, conf.GetStringSlice(configuration.INPUT_DIRECTORY),
		"INPUT_DIRECTORY must be exactly the content root")
	assert.False(t, conf.IsSet(""), "no empty-string key may be set")
}

// TestBuildRemyFixConfig_ForwardsPersistedLlmProviderAndModel wires
// types.SetGlobalUser to buildRemyFixConfig on a real configuration.Configuration,
// proving the developer's saved provider/model choice reaches the fix workflow's
// config under the exact keys remy-cli-extension reads (FlagProvider/FlagModel:
// "provider"/"model").
func TestBuildRemyFixConfig_ForwardsPersistedLlmProviderAndModel(t *testing.T) {
	const contentRoot = "/work/repo-root"

	base := configuration.NewWithOpts()
	types.SetGlobalUser(base, types.SettingLlmProvider, "ollama")
	types.SetGlobalUser(base, types.SettingLlmModel, "llama3.1")

	conf := buildRemyFixConfig(base, contentRoot)

	assert.Equal(t, "ollama", conf.GetString("provider"))
	assert.Equal(t, "llama3.1", conf.GetString("model"))
}

// TestBuildRemyFixConfig_NoProviderChosen guards the no-forced-default
// requirement: a developer who never chose a provider must not
// have "provider"/"model" keys set at all, matching the empty-string-key
// discipline the other flags already follow.
func TestBuildRemyFixConfig_NoProviderChosen(t *testing.T) {
	conf := buildRemyFixConfig(configuration.NewWithOpts(), "/work/repo-root")

	assert.False(t, conf.IsSet("provider"), "provider must not be set when the developer never chose one")
	assert.False(t, conf.IsSet("model"), "model must not be set when the developer never chose a provider")
}

// TestBuildRemyFixConfig_ProviderWithoutModel covers a provider that needs no
// explicit model (e.g. anthropic/openai): only "provider" is set.
func TestBuildRemyFixConfig_ProviderWithoutModel(t *testing.T) {
	base := configuration.NewWithOpts()
	types.SetGlobalUser(base, types.SettingLlmProvider, "anthropic")

	conf := buildRemyFixConfig(base, "/work/repo-root")

	assert.Equal(t, "anthropic", conf.GetString("provider"))
	assert.False(t, conf.IsSet("model"), "model must not be set when the developer never chose one")
}

// TestBuildRemyFixConfig_ModelWithoutProvider covers the (unlikely but
// possible) case of a persisted model with no provider selected: the model
// key must still be forwarded on its own, with no invented provider.
func TestBuildRemyFixConfig_ModelWithoutProvider(t *testing.T) {
	base := configuration.NewWithOpts()
	types.SetGlobalUser(base, types.SettingLlmModel, "llama3.1")

	conf := buildRemyFixConfig(base, "/work/repo-root")

	assert.False(t, conf.IsSet("provider"), "provider must not be set when the developer never chose one")
	assert.Equal(t, "llama3.1", conf.GetString("model"))
}

// TestBuildRemyFixConfig_ProviderSwitchDoesNotLeakStaleModel guards against a
// stale model value surviving a provider switch: buildRemyFixConfig must
// reflect base's CURRENT values on every call, never a value cached from an
// earlier call on a different base.
func TestBuildRemyFixConfig_ProviderSwitchDoesNotLeakStaleModel(t *testing.T) {
	first := configuration.NewWithOpts()
	types.SetGlobalUser(first, types.SettingLlmProvider, "ollama")
	types.SetGlobalUser(first, types.SettingLlmModel, "llama3.1")
	_ = buildRemyFixConfig(first, "/work/repo-root")

	second := configuration.NewWithOpts()
	types.SetGlobalUser(second, types.SettingLlmProvider, "anthropic")

	conf := buildRemyFixConfig(second, "/work/repo-root")

	assert.Equal(t, "anthropic", conf.GetString("provider"))
	assert.False(t, conf.IsSet("model"), "switching provider must not leak the previous provider's model")
}

// TestTryWithLLMProviderEnvLock_ReturnsFalseWithoutRunningFnWhenLocked guards the
// non-blocking path application/server relies on: it must never invoke fn, nor
// block, while the lock is held elsewhere.
func TestTryWithLLMProviderEnvLock_ReturnsFalseWithoutRunningFnWhenLocked(t *testing.T) {
	llmProviderEnvMu.Lock()
	defer llmProviderEnvMu.Unlock()

	called := false
	ok := TryWithLLMProviderEnvLock(func() { called = true })

	assert.False(t, ok)
	assert.False(t, called)
}

// TestTryWithLLMProviderEnvLock_RunsFnAndReturnsTrueWhenFree is the counterpart:
// when the lock is free, fn must run synchronously under it and TryLock must
// report success.
func TestTryWithLLMProviderEnvLock_RunsFnAndReturnsTrueWhenFree(t *testing.T) {
	called := false
	ok := TryWithLLMProviderEnvLock(func() { called = true })

	assert.True(t, ok)
	assert.True(t, called)
}

// TestWithLLMProviderEnvLock_RunsFnUnderExclusiveLock guards the blocking path
// used by the coalesced background worker.
func TestWithLLMProviderEnvLock_RunsFnUnderExclusiveLock(t *testing.T) {
	called := false
	WithLLMProviderEnvLock(func() { called = true })

	assert.True(t, called)
}
