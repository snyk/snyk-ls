package mcp_extension

import (
	"testing"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/app"
)

func Test_ExtensionEntryPoint(t *testing.T) {
	expectedTransportType := "stdio"
	engine := app.CreateAppEngineWithOptions()

	engineConfig := configuration.NewWithOpts(
		configuration.WithAutomaticEnv(),
	)
	engineConfig.Set("transport", expectedTransportType)
	engineConfig.Set(configuration.FLAG_EXPERIMENTAL, true)

	//register extension under test
	err := Init(engine)
	assert.Nil(t, err)

	go func() {
		err = engine.Init()
		assert.Nil(t, err)

		data, err := engine.InvokeWithConfig(WORKFLOWID_MCP, engineConfig)
		assert.Nil(t, err)
		assert.Empty(t, data)
	}()

	assert.Eventuallyf(t, func() bool {
		return expectedTransportType == engineConfig.GetString("transport") && engineConfig.GetBool(configuration.FLAG_EXPERIMENTAL)
	}, time.Minute, time.Millisecond, "open browser was not called")
}
