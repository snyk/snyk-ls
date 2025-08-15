package ls_extension

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/testutil"

	"github.com/snyk/go-application-framework/pkg/app"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

func Test_ExtensionEntryPoint(t *testing.T) {
	c := testutil.UnitTest(t)
	expectedLoglevel := "trace"
	expectedLogPath := t.TempDir()

	engine := app.CreateAppEngineWithOptions()

	//register extension under test
	err := Init(engine)
	assert.Nil(t, err)

	err = engine.Init()
	assert.Nil(t, err)

	engineConfig := configuration.NewWithOpts(
		configuration.WithAutomaticEnv(),
		configuration.WithCachingEnabled(configuration.NoCacheExpiration),
	)
	engineConfig.Set(configuration.DEBUG, true)
	engineConfig.Set("logLevelFlag", expectedLoglevel)
	engineConfig.Set("logPathFlag", expectedLogPath)
	engineConfig.Set("v", true)
	data, err := engine.InvokeWithConfig(WORKFLOWID_LS, engineConfig)
	assert.Nil(t, err)
	assert.Empty(t, data)

	assert.Equal(t, expectedLoglevel, c.LogLevel())
	assert.Equal(t, expectedLogPath, c.LogPath())
	assert.Equal(t, configCacheTTL, c.Engine().GetConfiguration().GetDuration(configuration.CONFIG_CACHE_TTL))
	assert.False(t, c.Engine().GetConfiguration().GetBool(configuration.CONFIG_CACHE_DISABLED))
}
