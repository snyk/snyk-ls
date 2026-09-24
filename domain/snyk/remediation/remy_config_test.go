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
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/app"
	"github.com/snyk/go-application-framework/pkg/configuration"
	gafMocks "github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

	conf := buildRemyFixConfig(configuration.NewWithOpts(), contentRoot, nil)

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

	conf := buildRemyFixConfig(base, contentRoot, nil)

	assert.Equal(t, "ollama", conf.GetString("provider"))
	assert.Equal(t, "llama3.1", conf.GetString("model"))
}

// TestBuildRemyFixConfig_NoProviderChosen guards the no-forced-default
// requirement: a developer who never chose a provider must not
// have "provider"/"model" keys set at all, matching the empty-string-key
// discipline the other flags already follow.
func TestBuildRemyFixConfig_NoProviderChosen(t *testing.T) {
	conf := buildRemyFixConfig(configuration.NewWithOpts(), "/work/repo-root", nil)

	assert.False(t, conf.IsSet("provider"), "provider must not be set when the developer never chose one")
	assert.False(t, conf.IsSet("model"), "model must not be set when the developer never chose a provider")
}

// TestBuildRemyFixConfig_ProviderWithoutModel covers a provider that needs no
// explicit model (e.g. anthropic/openai): only "provider" is set.
func TestBuildRemyFixConfig_ProviderWithoutModel(t *testing.T) {
	base := configuration.NewWithOpts()
	types.SetGlobalUser(base, types.SettingLlmProvider, "anthropic")

	conf := buildRemyFixConfig(base, "/work/repo-root", nil)

	assert.Equal(t, "anthropic", conf.GetString("provider"))
	assert.False(t, conf.IsSet("model"), "model must not be set when the developer never chose one")
}

// TestBuildRemyFixConfig_ModelWithoutProvider covers the edge case of a
// persisted model with no provider selected: the model key must still be
// forwarded on its own, with no invented provider.
func TestBuildRemyFixConfig_ModelWithoutProvider(t *testing.T) {
	base := configuration.NewWithOpts()
	types.SetGlobalUser(base, types.SettingLlmModel, "llama3.1")

	conf := buildRemyFixConfig(base, "/work/repo-root", nil)

	assert.False(t, conf.IsSet(remyProviderConfigKey), "provider must not be set when the developer never chose one")
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
	_ = buildRemyFixConfig(first, "/work/repo-root", nil)

	second := configuration.NewWithOpts()
	types.SetGlobalUser(second, types.SettingLlmProvider, "anthropic")

	conf := buildRemyFixConfig(second, "/work/repo-root", nil)

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

func TestBuildRemyFixConfig_ForwardsSeverityFilter(t *testing.T) {
	logger := zerolog.Nop()
	base := configuration.NewWithOpts()
	sf := types.NewSeverityFilter(true, true, false, false)
	types.SetSeverityFilterOnConfig(base, &sf, &logger)

	conf := buildRemyFixConfig(base, "/work/repo-root", nil)

	assert.Equal(t, "critical,high", conf.GetString(remySeverityFilterConfigKey))
}

func TestBuildRemyFixConfig_ForwardsEverySeverityWhenNothingFiltered(t *testing.T) {
	logger := zerolog.Nop()
	base := configuration.NewWithOpts()
	sf := types.DefaultSeverityFilter()
	types.SetSeverityFilterOnConfig(base, &sf, &logger)

	conf := buildRemyFixConfig(base, "/work/repo-root", nil)

	assert.Equal(t, "critical,high,medium,low", conf.GetString(remySeverityFilterConfigKey))
}

// "" from remySeverityFilter means no severity is enabled, never "all of them",
// so the two states cannot collapse into one config.
func TestRemySeverityFilter_EmptyOnlyWhenNothingEnabled(t *testing.T) {
	assert.Equal(t, "critical,high,medium,low", remySeverityFilter(types.DefaultSeverityFilter()))
	assert.Empty(t, remySeverityFilter(types.NewSeverityFilter(false, false, false, false)))
}

func TestBuildRemyFixConfig_SeverityFilterCriticalOnly(t *testing.T) {
	logger := zerolog.Nop()
	base := configuration.NewWithOpts()
	sf := types.NewSeverityFilter(true, false, false, false)
	types.SetSeverityFilterOnConfig(base, &sf, &logger)

	conf := buildRemyFixConfig(base, "/work/repo-root", nil)

	assert.Equal(t, "critical", conf.GetString(remySeverityFilterConfigKey))
}

// A severity floor would round critical+medium up to critical,high,medium.
// The exact-set flag has to keep the hole at high.
func TestBuildRemyFixConfig_SeverityFilterKeepsGaps(t *testing.T) {
	logger := zerolog.Nop()
	base := configuration.NewWithOpts()
	sf := types.NewSeverityFilter(true, false, true, false)
	types.SetSeverityFilterOnConfig(base, &sf, &logger)

	conf := buildRemyFixConfig(base, "/work/repo-root", nil)

	assert.Equal(t, "critical,medium", conf.GetString(remySeverityFilterConfigKey))
}

// Without the guard the empty filter string reaches remy as no filter and
// fixes every severity.
func TestGafRunner_SkipsInvocationWhenEverySeverityDisabled(t *testing.T) {
	logger := zerolog.Nop()
	base := configuration.NewWithOpts()
	sf := types.NewSeverityFilter(false, false, false, false)
	types.SetSeverityFilterOnConfig(base, &sf, &logger)

	ctrl := gomock.NewController(t)
	mockEngine := gafMocks.NewMockEngine(ctrl)
	mockEngine.EXPECT().GetConfiguration().Return(base).AnyTimes()
	mockEngine.EXPECT().Invoke(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

	assert.NoError(t, gafRunner(context.Background(), mockEngine, "/work/repo-root", nil))
}

func TestGafRunner_InvokesWhenSomeSeverityEnabled(t *testing.T) {
	logger := zerolog.Nop()
	base := configuration.NewWithOpts()
	sf := types.NewSeverityFilter(true, false, false, false)
	types.SetSeverityFilterOnConfig(base, &sf, &logger)

	ctrl := gomock.NewController(t)
	mockEngine := gafMocks.NewMockEngine(ctrl)
	mockEngine.EXPECT().GetConfiguration().Return(base).AnyTimes()
	mockEngine.EXPECT().Invoke(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).Times(1)

	assert.NoError(t, gafRunner(context.Background(), mockEngine, "/work/repo-root", nil))
}

func TestBuildRemyFixConfig_ScopesToRequestedFindingIDs(t *testing.T) {
	conf := buildRemyFixConfig(configuration.NewWithOpts(), "/work/repo-root", []string{"finding-1", "finding-2"})

	assert.Equal(t, "finding-1,finding-2", conf.GetString(remyIssueIDsConfigKey))
	assert.True(t, conf.GetBool("auto-approve"), "issue-ids only takes effect with auto-approve")
}

func TestBuildRemyFixConfig_NoFindingIDsLeavesIssueIDsUnset(t *testing.T) {
	for name, ids := range map[string][]string{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			conf := buildRemyFixConfig(configuration.NewWithOpts(), "/work/repo-root", ids)
			assert.False(t, conf.IsSet(remyIssueIDsConfigKey), "issue-ids must stay unset")
		})
	}
}

func TestGafRunner_DropsScopeWhenWorkflowHasNoIssueIDsFlag(t *testing.T) {
	tests := []struct {
		name          string
		registerFlag  bool
		wantIssueIDs  string
		wantScopedSet bool
	}{
		{name: "flag present", registerFlag: true, wantIssueIDs: "finding-1,finding-2", wantScopedSet: true},
		{name: "flag absent", registerFlag: false, wantScopedSet: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got configuration.Configuration
			eng := engineWithFixWorkflow(t, tt.registerFlag, func(conf configuration.Configuration) {
				got = conf
			})

			require.NoError(t, gafRunner(context.Background(), eng, "/work/repo-root", []string{"finding-1", "finding-2"}))

			require.NotNil(t, got, "the fix workflow must have been invoked")
			assert.Equal(t, tt.wantScopedSet, got.IsSet(remyIssueIDsConfigKey))
			assert.Equal(t, tt.wantIssueIDs, got.GetString(remyIssueIDsConfigKey))
		})
	}
}

// The real "fix" workflow lives in a module snyk-ls does not compile against.
// withIssueIDs stands in for a newer bundled remy.
func engineWithFixWorkflow(t *testing.T, withIssueIDs bool, capture func(configuration.Configuration)) workflow.Engine {
	t.Helper()
	eng := app.CreateAppEngineWithOptions(app.WithConfiguration(configuration.NewWithOpts()))
	flagSet := pflag.NewFlagSet("fix", pflag.ContinueOnError)
	if withIssueIDs {
		flagSet.String(remyIssueIDsConfigKey, "", "")
	}
	_, err := eng.Register(
		workflow.NewWorkflowIdentifier("fix"),
		workflow.ConfigurationOptionsFromFlagset(flagSet),
		func(ictx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
			capture(ictx.GetConfiguration())
			return nil, nil
		},
	)
	require.NoError(t, err)
	require.NoError(t, eng.Init())

	sf := types.NewSeverityFilter(true, true, true, true)
	logger := zerolog.Nop()
	types.SetSeverityFilterOnConfig(eng.GetConfiguration(), &sf, &logger)
	return eng
}

func TestGafRunner_DropsScopeWhenWorkflowIsNotRegistered(t *testing.T) {
	logger := zerolog.Nop()
	base := configuration.NewWithOpts()
	sf := types.NewSeverityFilter(true, true, true, true)
	types.SetSeverityFilterOnConfig(base, &sf, &logger)

	ctrl := gomock.NewController(t)
	mockEngine := gafMocks.NewMockEngine(ctrl)
	mockEngine.EXPECT().GetConfiguration().Return(base).AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(&logger).AnyTimes()
	mockEngine.EXPECT().GetWorkflow(gomock.Any()).Return(nil, false).AnyTimes()
	mockEngine.EXPECT().Invoke(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).Times(1)

	assert.NoError(t, gafRunner(context.Background(), mockEngine, "/work/repo-root", []string{"finding-1"}))
}
