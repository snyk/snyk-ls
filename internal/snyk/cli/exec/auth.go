package exec

import (
	"context"
	"os/exec"

	"github.com/rs/zerolog/log"
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
