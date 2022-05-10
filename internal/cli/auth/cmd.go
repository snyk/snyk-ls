package auth

import (
	"context"
	"os/exec"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/config"
)

func buildCLICmd(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, config.CurrentConfig.CliPath(), args...)
	log.Info().Str("command", cmd.String()).Msg("running Snyk CLI command")
	return cmd
}

func runCLICmd(ctx context.Context, cmd *exec.Cmd) error {
	go func() {
		<-ctx.Done()
		if ctx.Err() == context.DeadlineExceeded || ctx.Err() == context.Canceled {
			if cmd != nil && cmd.Process != nil && cmd.ProcessState != nil {
				err := cmd.Process.Kill()
				if err != nil {
					log.Err(err).Msg("error from kill")
				}
			}
		}
	}()
	// check for early cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	err := cmd.Run()
	if err == nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		log.Err(err).Msg("error while calling Snyk CLI command")
	}

	return nil
}
