package auth

import (
	"context"
	"errors"
	"os/exec"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/presentation/lsp"
)

// todo authenticate does both CLI and non-cli stuff. Can we separate concerns here?
type Authenticator struct {
	errorReporter error_reporting.ErrorReporter
}

func New(errorReporter error_reporting.ErrorReporter) *Authenticator {
	return &Authenticator{errorReporter: errorReporter}
}

func (a *Authenticator) Authenticate(ctx context.Context) {
	token, err := GetToken(ctx)
	if err != nil {
		if errors.Is(err, ErrEmptyAPIToken) {
			err := a.auth(ctx)
			if err != nil {
				log.Err(err).Str("method", "Authenticate").Msg("error while authenticating")
				a.errorReporter.CaptureError(err)
			}
			token, err = GetToken(ctx)
			if err != nil {
				log.Err(err).Str("method", "Authenticate").Msg("error getting token after reauthenticating")
				a.errorReporter.CaptureError(err)
			}
		} else {
			log.Err(err).Str("method", "Authenticate").Msg("error while getting token, and is not an ErrEmptyApiToken")
			a.errorReporter.CaptureError(err)
		}
	} else {
		config.CurrentConfig().SetToken(token)
	}
	notification.Send(lsp.AuthenticationParams{Token: token})
}

// Auth represents the `snyk auth` command.
func (a *Authenticator) auth(ctx context.Context) error {
	cmd, err := a.authCmd(ctx)
	if err != nil {
		return err
	}
	return runCLICmd(ctx, cmd)
}

func (a *Authenticator) authCmd(ctx context.Context) (*exec.Cmd, error) {
	log.Info().Msg("authenticate Snyk CLI with a Snyk account")

	// flags and other arguments should be added here (e.g. --insecure etc)
	args := []string{"auth"}

	return buildCLICmd(ctx, args...), nil
}
