package services

import (
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
