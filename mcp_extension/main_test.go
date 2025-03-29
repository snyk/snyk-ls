package mcp_extension

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/app"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/application/config"
)

func Test_ExtensionEntryPoint(t *testing.T) {
	expectedLoglevel := "trace"
	expectedLogPath := t.TempDir()
	expectedTransportType := "sse"
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
	engineConfig.Set("transport", "sse")
	data, err := engine.InvokeWithConfig(WORKFLOWID_MCP, engineConfig)
	assert.Nil(t, err)
	assert.Empty(t, data)

	c := config.CurrentConfig()
	assert.Equal(t, expectedLoglevel, c.LogLevel())
	assert.Equal(t, expectedLogPath, c.LogPath())
	assert.Equal(t, expectedTransportType, string(c.GetMcpTransportType()))
}
