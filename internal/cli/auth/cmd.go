package auth

import (
	"context"
	"os/exec"

	"github.com/snyk/snyk-ls/config/environment"
)

func buildCLICmd(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, environment.CliPath(), args...)
	logger.
		WithField("method", "buildCLICmd").
		WithField("command", cmd.String()).
		Info(ctx, "running Snyk CLI command")
	return cmd
}

func runCLICmd(ctx context.Context, cmd *exec.Cmd) error {
	go func() {
		<-ctx.Done()
		if ctx.Err() == context.DeadlineExceeded || ctx.Err() == context.Canceled {
			if cmd != nil && cmd.Process != nil && cmd.ProcessState != nil {
				err := cmd.Process.Kill()
				if err != nil {
					logger.
						WithField("method", "runCLICmd").
						WithError(err).
						Error(ctx, "error from kill")
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
		logger.
			WithField("method", "runCLICmd").
			WithError(err).
			Error(ctx, "error while caling Snyk CLI command")
	}

	return nil
}
