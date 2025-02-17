package ls_extension

import (
	"testing"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/app"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

func Test_ExtensionEntryPoint(t *testing.T) {
	expectedLoglevel := "trace"
	expectedLogPath := types.FilePath(t.TempDir())

	engine := app.CreateAppEngineWithOptions()

	//register extension under test
	err := Init(engine)
	assert.Nil(t, err)

	err = engine.Init()
	assert.Nil(t, err)

	engineConfig := configuration.NewWithOpts(
		configuration.WithAutomaticEnv(),
	)
	engineConfig.Set(configuration.DEBUG, true)
	engineConfig.Set("logLevelFlag", expectedLoglevel)
	engineConfig.Set("logPathFlag", expectedLogPath)
	engineConfig.Set("v", true)
	data, err := engine.InvokeWithConfig(WORKFLOWID_LS, engineConfig)
	assert.Nil(t, err)
	assert.Empty(t, data)

	c := config.CurrentConfig()
	assert.Equal(t, expectedLoglevel, c.LogLevel())
	assert.Equal(t, expectedLogPath, c.LogPath())
}
