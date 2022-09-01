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

		var authString = `Now redirecting you to our auth page, go ahead and log in,
		and once the auth is complete, return to this prompt and you'll
		be ready to start using snyk.
		
		If you can't wait use this url:
		https://app.snyk.io/login?token=<TOKEN>&utm_medium=cli&utm_source=cli&utm_campaign=cli&os=darwin&docker=false`

		expectedURL := "https://app.snyk.io/login?token=<TOKEN>&utm_medium=cli&utm_source=cli&utm_campaign=cli&os=darwin&docker=false"

		err := provider.setAuthURL(authString)

		assert.NoError(t, err)
		assert.Equal(t, expectedURL, provider.authUrl)
	})

	t.Run("works for a custom endpoint", func(t *testing.T) {
		testutil.UnitTest(t)
		provider := &CliAuthenticationProvider{}

		var authString = `Now redirecting you to our auth page, go ahead and log in,
		and once the auth is complete, return to this prompt and you'll
		be ready to start using snyk.
		
		If you can't wait use this url:
		https://myOwnCompanyURL/login?token=<TOKEN>&utm_medium=cli&utm_source=cli&utm_campaign=cli&os=darwin&docker=false`

		expectedURL := "https://myOwnCompanyURL/login?token=<TOKEN>&utm_medium=cli&utm_source=cli&utm_campaign=cli&os=darwin&docker=false"

		err := provider.setAuthURL(authString)

		assert.NoError(t, err)
		assert.Equal(t, expectedURL, provider.authUrl)
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
