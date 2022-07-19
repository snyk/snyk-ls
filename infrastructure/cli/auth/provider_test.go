package auth

import (
	"context"
	"testing"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"

	"github.com/stretchr/testify/assert"
)

// todo: int tests for interface public methods ?

func TestAuth_authCmd(t *testing.T) {
	testutil.UnitTest(t)
	ctx := context.Background()
	provider := &CliAuthenticationProvider{}

	authCmd, err := provider.authCmd(ctx)

	assert.NoError(t, err)
	assertCmd(t, []string{"auth"}, authCmd)
}

func TestConfig_configGetAPICmd(t *testing.T) {
	ctx := context.Background()
	provider := &CliAuthenticationProvider{}

	configGetAPICmd, err := provider.configGetAPICmd(ctx)

	assert.NoError(t, err)
	assertCmd(t, []string{"config", "get", "api"}, configGetAPICmd)
}

func TestBuildCLICmd(t *testing.T) {
	t.Run("Insecure is respected", func(t *testing.T) {
		testutil.UnitTest(t)
		ctx := context.Background()
		provider := &CliAuthenticationProvider{}
		config.CurrentConfig().SetCliSettings(&config.CliSettings{
			Insecure: true,
		})

		cmd := provider.buildCLICmd(ctx, "auth")

		assert.Equal(t, []string{".", "auth", "--insecure"}, cmd.Args)
	})

	t.Run("Api endpoint is respected", func(t *testing.T) {
		testutil.UnitTest(t)
		ctx := context.Background()
		provider := &CliAuthenticationProvider{}
		config.CurrentConfig().UpdateApiEndpoints("https://app.snyk.io/api")

		cmd := provider.buildCLICmd(ctx, "auth")

		assert.Contains(t, cmd.Env, "SNYK_API=https://app.snyk.io/api")
	})

	t.Run("Telemetry disabled setting is respected", func(t *testing.T) {
		testutil.UnitTest(t)
		ctx := context.Background()
		provider := &CliAuthenticationProvider{}
		config.CurrentConfig().SetTelemetryEnabled(false)

		cmd := provider.buildCLICmd(ctx, "auth")

		assert.Contains(t, cmd.Env, "SNYK_CFG_DISABLE_ANALYTICS=1")
	})

	t.Run("Telemetry env var isn't set if telemetry enabled", func(t *testing.T) {
		testutil.UnitTest(t)
		ctx := context.Background()
		provider := &CliAuthenticationProvider{}

		cmd := provider.buildCLICmd(ctx, "auth")

		assert.NotContains(t, cmd.Env, "SNYK_CFG_DISABLE_ANALYTICS=1")
	})
}
