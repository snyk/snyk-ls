package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	errorreporting "github.com/snyk/snyk-ls/domain/observability/error_reporting"
	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/infrastructure/services"
)

func Test_autoAuthenticationDisabled_doesNotAuthenticate(t *testing.T) {
	t.Run("Does not authenticate when auto-auth is disabled", getAutoAuthenticationTest(false))
	t.Run("Authenticates when auto-auth is disabled", getAutoAuthenticationTest(true))
}

func getAutoAuthenticationTest(autoAuthentication bool) func(t *testing.T) {
	return func(t *testing.T) {
		// Arrange
		config.CurrentConfig().SetToken("")
		config.CurrentConfig().SetAutomaticAuthentication(autoAuthentication)
		analytics := ux2.NewTestAnalytics()
		provider := NewFakeCliAuthenticationProvider().(*FakeAuthenticationProvider)
		authenticator := services.NewAuthenticationService(provider, analytics)
		initializer := NewInitializer(authenticator, errorreporting.NewTestErrorReporter(), analytics)

		// Act
		initializer.Init()

		// Assert
		assert.Equal(t, autoAuthentication, provider.IsAuthenticated)
	}
}
