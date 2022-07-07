package auth

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testutil"

	"github.com/stretchr/testify/assert"
)

func TestAuthenticateToken(t *testing.T) {
	testutil.UnitTest(t)
	ctx := context.Background()

	t.Run("Gets token, if set", func(t *testing.T) {
		fakeToken := uuid.New().String()
		provider := &TestAuthenticationProvider{
			token: fakeToken,
		}
		authenticator := New(error_reporting.NewTestErrorReporter(), provider)
		authenticator.Authenticate(ctx)

		assert.Equal(t, fakeToken, config.CurrentConfig().Token())
	})

	t.Run("Updates token in configuration, if not authenticated", func(t *testing.T) {
		provider := &TestAuthenticationProvider{
			token: "",
		}
		authenticator := New(error_reporting.NewTestErrorReporter(), provider)
		authenticator.Authenticate(ctx)

		assert.Equal(t, provider.token, config.CurrentConfig().Token())
	})
}
