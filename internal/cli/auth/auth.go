package auth

import (
	"context"
	"errors"
	"os/exec"

	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/error_reporting"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/lsp"
)

var logger = environment.Logger

// Auth represents the `snyk auth` command.
func Auth(ctx context.Context) error {
	cmd, err := authCmd(ctx)
	if err != nil {
		return err
	}
	return runCLICmd(ctx, cmd)
}

func authCmd(ctx context.Context) (*exec.Cmd, error) {
	logger.
		WithField("method", "authCmd").
		Debug(ctx, "authenticate Snyk CLI with a Snyk account")

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
				logger.
					WithField("method", "Authenticate").
					WithError(err).
					Error(ctx, "couldn't authenticate")
			}
			token, err = GetToken(ctx)
			if err != nil {
				logger.
					WithField("method", "Authenticate").
					WithError(err).
					Error(ctx, "couldn't get token")
			}
		} else {
			logger.
				WithField("method", "Authenticate").
				WithError(err).
				Error(ctx, "couldn't get token")
		}
		error_reporting.CaptureError(err)
	} else {
		err = environment.SetToken(token)
		if err != nil {
			logger.
				WithField("method", "Authenticate").
				WithError(err).
				Error(ctx, "couldn't add token to environment")
			error_reporting.CaptureError(err)
		}
	}
	notification.Send(lsp.AuthenticationParams{Token: token})
}
