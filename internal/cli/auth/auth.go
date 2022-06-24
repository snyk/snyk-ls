package auth

import (
	"context"
	"errors"
	"os/exec"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/di"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/lsp"
)

// Auth represents the `snyk auth` command.
func Auth(ctx context.Context) error {
	cmd, err := authCmd(ctx)
	if err != nil {
		return err
	}
	return runCLICmd(ctx, cmd)
}

func authCmd(ctx context.Context) (*exec.Cmd, error) {
	log.Info().Msg("authenticate Snyk CLI with a Snyk account")

	// flags and other arguments should be added here (e.g. --insecure etc)
	args := []string{"auth"}

	return buildCLICmd(ctx, args...), nil
}

func Authenticate(ctx context.Context) {
	token, err := GetToken(ctx)
	if err != nil {
		if errors.Is(err, ErrEmptyAPIToken) {
			err := Auth(ctx)
			if err != nil {
				log.Err(err).Str("method", "Authenticate").Msg("error while authenticating")
				di.ErrorReporter().CaptureError(err)
			}
			token, err = GetToken(ctx)
			if err != nil {
				log.Err(err).Str("method", "Authenticate").Msg("error getting token after reauthenticating")
				di.ErrorReporter().CaptureError(err)
			}
		} else {
			log.Err(err).Str("method", "Authenticate").Msg("error while getting token, and is not an ErrEmptyApiToken")
			di.ErrorReporter().CaptureError(err)
		}
	} else {
		config.CurrentConfig().SetToken(token)
	}
	notification.Send(lsp.AuthenticationParams{Token: token})
	// initialize analytics anew, as we now have a user!
	di.InitializeAnalytics()
}
