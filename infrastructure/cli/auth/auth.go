package auth

import (
	"context"
	"errors"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/presentation/lsp"
)

// todo authenticate does both CLI and non-cli stuff. Can we separate concerns here?
type Authenticator struct {
	errorReporter error_reporting.ErrorReporter
	authProvider  AuthenticationProvider
}

func New(errorReporter error_reporting.ErrorReporter, authProvider AuthenticationProvider) *Authenticator {
	return &Authenticator{errorReporter, authProvider}
}

func (a *Authenticator) Authenticate(ctx context.Context) {
	token, err := a.authProvider.GetToken(ctx)
	if err == nil {
		config.CurrentConfig().SetToken(token)
		return
	}

	if !errors.Is(err, ErrEmptyAPIToken) {
		log.Err(err).Str("method", "Authenticate").Msg("error while getting token, and is not an ErrEmptyApiToken")
		a.errorReporter.CaptureError(err)
		notification.Send(lsp.AuthenticationParams{Token: token})
		return
	}

	notification.Send(sglsp.ShowMessageParams{Type: sglsp.Info, Message: "Authenticating to Snyk. This could open a browser window."})

	err = a.authProvider.Authenticate(ctx)
	if err != nil {
		log.Err(err).Str("method", "Authenticate").Msg("error while authenticating")
		a.errorReporter.CaptureError(err)
	}
	token, err = a.authProvider.GetToken(ctx)
	if err != nil {
		log.Err(err).Str("method", "Authenticate").Msg("error getting token after reauthenticating")
		a.errorReporter.CaptureError(err)
	}

	config.CurrentConfig().SetToken(token)
	notification.Send(lsp.AuthenticationParams{Token: token})
}

func (a *Authenticator) ClearAuthentication(ctx context.Context) error {
	return a.authProvider.ClearToken(ctx)
}
