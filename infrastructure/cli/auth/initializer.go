package auth

import (
	"context"
	"os"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/internal/notification"
)

type Initializer struct {
	authenticator snyk.AuthenticationService
	errorReporter error_reporting.ErrorReporter
	analytics     ux.Analytics
}

func NewInitializer(authenticator snyk.AuthenticationService, errorReporter error_reporting.ErrorReporter, analytics ux.Analytics) *Initializer {
	return &Initializer{
		authenticator,
		errorReporter,
		analytics,
	}
}

func (i *Initializer) Init() {
	cli.Mutex.Lock()
	defer cli.Mutex.Unlock()

	authenticated := config.CurrentConfig().Authenticated()
	if authenticated {
		return
	}

	notification.Send(sglsp.ShowMessageParams{Type: sglsp.Info, Message: "Authenticating to Snyk. This could open a browser window."})

	token, err := i.authenticator.Provider().Authenticate(context.Background())
	if token == "" || err != nil {
		log.Error().Err(err).Msg("Failed to authenticate. Terminating server.")
		i.errorReporter.CaptureError(err)
		os.Exit(1) // terminate server since unrecoverable from authentication error
	}

	i.authenticator.UpdateToken(token)
}
