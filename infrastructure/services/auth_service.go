package services

import (
	"context"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/notification"
)

type AuthenticationService struct {
	authenticator snyk.AuthenticationProvider
	analytics     ux.Analytics
}

func NewAuthenticationService(authenticator snyk.AuthenticationProvider, analytics ux.Analytics) *AuthenticationService {
	return &AuthenticationService{authenticator, analytics}
}

func (a AuthenticationService) Provider() snyk.AuthenticationProvider {
	return a.authenticator
}

func (a *AuthenticationService) Authenticate(ctx context.Context) (string, error) {
	token, err := a.Provider().Authenticate(ctx)
	if token == "" || err != nil {
		log.Error().Err(err).Msg("Failed to authenticate")
		return "", err
	}
	a.UpdateToken(token, true)

	return token, err
}

func (a AuthenticationService) UpdateToken(newToken string, sendNotification bool) {
	oldToken := config.CurrentConfig().Token()
	config.CurrentConfig().SetToken(newToken)

	if sendNotification {
		notification.Send(lsp.AuthenticationParams{Token: newToken})
	}

	if oldToken != newToken {
		a.analytics.Identify()
	}
}
