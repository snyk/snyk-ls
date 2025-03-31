package mcp_extension

import (
	"testing"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/app"
)

func Test_ExtensionEntryPoint(t *testing.T) {
	expectedTransportType := "sse"
	engine := app.CreateAppEngineWithOptions()

	//register extension under test
	err := Init(engine)
	assert.Nil(t, err)

	go func() {
		err = engine.Init()
		assert.Nil(t, err)

		engineConfig := configuration.NewWithOpts(
			configuration.WithAutomaticEnv(),
		)
		engineConfig.Set("transport", expectedTransportType)
		data, err := engine.InvokeWithConfig(WORKFLOWID_MCP, engineConfig)
		assert.Nil(t, err)
		assert.Empty(t, data)
	}()

	assert.Eventuallyf(t, func() bool {
		return expectedTransportType == engine.GetConfiguration().GetString("transport")
	}, time.Minute, time.Millisecond, "open browser was not called")
}
