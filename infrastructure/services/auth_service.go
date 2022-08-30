package services

import (
	"context"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/notification"
)

type AuthenticationService struct {
	authenticator snyk.AuthenticationProvider
	analytics     ux.Analytics
	errorReporter error_reporting.ErrorReporter
}

func NewAuthenticationService(authenticator snyk.AuthenticationProvider, analytics ux.Analytics, errorReporter error_reporting.ErrorReporter) *AuthenticationService {
	return &AuthenticationService{authenticator, analytics, errorReporter}
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

func (a AuthenticationService) Logout(ctx context.Context) {
	err := a.Provider().ClearAuthentication(ctx)
	if err != nil {
		log.Error().Err(err).Str("method", "Logout").Msg("Failed to log out.")
		a.errorReporter.CaptureError(err)
		return
	}

	notification.Send(lsp.AuthenticationParams{Token: ""})

	workspace.Get().ClearIssues(ctx)
}
