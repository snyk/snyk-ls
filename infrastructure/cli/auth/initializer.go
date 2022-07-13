package auth

import (
	"context"
	"os"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/notification"
)

type Initializer struct {
	authenticator snyk.AuthenticationProvider
	errorReporter error_reporting.ErrorReporter
}

func NewInitializer(authenticator snyk.AuthenticationProvider, errorReporter error_reporting.ErrorReporter) *Initializer {
	return &Initializer{
		authenticator,
		errorReporter,
	}
}

func (i *Initializer) Init() {
	authenticated := config.CurrentConfig().Authenticated()

	if authenticated {
		return
	}

	notification.Send(sglsp.ShowMessageParams{Type: sglsp.Info, Message: "Authenticating to Snyk. This could open a browser window."})

	token, err := i.authenticator.Authenticate(context.Background())
	if token == "" || err != nil {
		log.Error().Err(err).Msg("Failed to authenticate. Terminating server.")
		i.errorReporter.CaptureError(err)
		os.Exit(1) // terminate server since unrecoverable from authentication error
	}

	config.CurrentConfig().SetToken(token)
	notification.Send(lsp.AuthenticationParams{Token: token})
}
