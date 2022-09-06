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

func TestSetAuthURLCmd(t *testing.T) {
	t.Run("works for the default endpoint", func(t *testing.T) {
		testutil.UnitTest(t)
		provider := &CliAuthenticationProvider{}

		var expectedURL = "https://app.snyk.io/login?token=<TOKEN>&utm_medium=cli&utm_source=cli&utm_campaign=cli&os=darwin&docker=false"

		actualURL := provider.getAuthURL(expectedURL)

		assert.Equal(t, expectedURL, actualURL)
	})

	t.Run("works for a custom endpoint", func(t *testing.T) {
		testutil.UnitTest(t)
		provider := &CliAuthenticationProvider{}

		var expectedURL = "https://myOwnCompanyURL/login?token=<TOKEN>&utm_medium=cli&utm_source=cli&utm_campaign=cli&os=darwin&docker=false"

		actualURL := provider.getAuthURL(expectedURL)

		assert.Equal(t, expectedURL, actualURL)
	})

	t.Run("works when URL is in a substring", func(t *testing.T) {
		testutil.UnitTest(t)
		provider := &CliAuthenticationProvider{}

		var stringWithURL = "If auth does not automatically redirect you, copy this auth link: https://app.snyk.io/login?token=<TOKEN>&utm_medium=cli&utm_source=cli&utm_campaign=cli&os=darwin&docker=false"
		var expectedURL = "https://app.snyk.io/login?token=<TOKEN>&utm_medium=cli&utm_source=cli&utm_campaign=cli&os=darwin&docker=false"

		actualURL := provider.getAuthURL(stringWithURL)

		assert.Equal(t, expectedURL, actualURL)
	})

	t.Run("errors when there is a problem extracting the auth url", func(t *testing.T) {
		testutil.UnitTest(t)
		provider := &CliAuthenticationProvider{}

		var badURL = "https://invlidAuthURL.com"

		actualURL := provider.getAuthURL(badURL)

		assert.Equal(t, actualURL, "")
	})
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
