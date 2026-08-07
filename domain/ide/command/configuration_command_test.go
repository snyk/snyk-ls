package command

import (
	"context"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

func TestConfigurationCommand_Execute(t *testing.T) {
	engine := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockServer := mock_types.NewMockServer(ctrl)

	cmdData := types.CommandData{
		CommandId: types.WorkspaceConfigurationCommand,
	}

	cmd := &configurationCommand{
		command:        cmdData,
		srv:            mockServer,
		logger:         engine.GetLogger(),
		engine:         engine,
		configResolver: testutil.DefaultConfigResolver(engine),
	}

	result, err := cmd.Execute(context.Background())
	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Verify the response is an HTML string
	html, ok := result.(string)
	assert.True(t, ok, "Result should be a string")
	assert.NotEmpty(t, html, "HTML content should not be empty")
}

func TestConstructSettingsFromConfig_AdditionalParamsAndEnv(t *testing.T) {
	engine := testutil.UnitTest(t)
	r := testutil.DefaultConfigResolver(engine)

	// Simulate what applyCliConfig writes for additional_parameters
	types.SetGlobalDeferredFolderScope(engine.GetConfiguration(), types.SettingCliAdditionalOssParameters, []string{"--debug", "--all-projects"})
	// Simulate what applyEnvironment writes for additional_environment (after our change)
	types.SetGlobalUser(engine.GetConfiguration(), types.SettingAdditionalEnvironment, "A=B;C=D")

	settings, _ := ConstructSettingsFromConfig(engine, r)

	paramsVal, ok := settings[types.SettingAdditionalParameters]
	assert.True(t, ok, "additional_parameters must be present in settings map")
	paramsStr, ok := paramsVal.(string)
	assert.True(t, ok, "additional_parameters value must be a string")
	// All params present; order may vary since they were stored as a slice
	for _, p := range []string{"--debug", "--all-projects"} {
		assert.Contains(t, paramsStr, p)
	}
	// Must be space-joined
	assert.Equal(t, 1, strings.Count(paramsStr, " "))

	envVal, ok := settings[types.SettingAdditionalEnvironment]
	assert.True(t, ok, "additional_environment must be present in settings map")
	assert.Equal(t, "A=B;C=D", envVal)
}

// Test_computeEffectiveConfig_IncludesAmbientCanaryAutonomy guards computeEffectiveConfig
// as the one non-generic place a new per-folder dialog setting must be registered —
// omitting it here renders the setting blank in the dialog even though
// registration/storage/transmission are all otherwise correct.
func Test_computeEffectiveConfig_IncludesAmbientCanaryAutonomy(t *testing.T) {
	engine := testutil.UnitTest(t)
	fc := &types.FolderConfig{FolderPath: "/path/to/folder"}
	fc.ConfigResolver = testutil.DefaultConfigResolver(engine)

	effectiveConfig := computeEffectiveConfig(fc)

	_, ok := effectiveConfig[types.SettingAmbientCanaryAutonomy]
	assert.True(t, ok, "computeEffectiveConfig must include ambient_canary_autonomy so the dialog can render it")
}
