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

func Authenticate() {
	ctx := context.Background()
	token, err := GetToken(ctx)
	if err != nil {
		if errors.Is(err, ErrEmptyAPIToken) {
			err := Auth(ctx)
			if err != nil {
				log.Err(err).Str("method", "Authenticate")
			}
			token, err = GetToken(ctx)
			if err != nil {
				log.Err(err).Str("method", "Authenticate")
			}
		} else {
			log.Err(err).Str("method", "Authenticate")
		}
		di.ErrorReporter().CaptureError(err)
	} else {
		err = config.CurrentConfig().SetToken(token)
		if err != nil {
			log.Err(err).Str("method", "Authenticate")
			di.ErrorReporter().CaptureError(err)
		}
	}
	notification.Send(lsp.AuthenticationParams{Token: token})
}
