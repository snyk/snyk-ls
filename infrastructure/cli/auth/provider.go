package auth

import (
	"context"
	"errors"
	"os/exec"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
)

type AuthenticationProvider interface {
	Authenticate(ctx context.Context) error
	GetToken(ctx context.Context) (string, error)
	ClearToken(ctx context.Context) error
}

type CliAuthenticationProvider struct {
}

var ErrEmptyAPIToken = errors.New("auth-provider: api token is not set")

func NewCliAuthenticationProvider() AuthenticationProvider {
	return &CliAuthenticationProvider{}
}

// Auth represents the `snyk auth` command.
func (a *CliAuthenticationProvider) Authenticate(ctx context.Context) error {
	cmd, err := a.authCmd(ctx)
	if err != nil {
		return err
	}

	var out strings.Builder
	cmd.Stdout = &out

	err = a.runCLICmd(ctx, cmd)
	str := out.String()
	log.Info().Str("output", str).Msg("auth Snyk CLI")
	return err
}

func (a *CliAuthenticationProvider) authCmd(ctx context.Context) (*exec.Cmd, error) {
	log.Info().Msg("authenticate Snyk CLI with a Snyk account")

	// flags and other arguments should be added here (e.g. --insecure etc)
	args := []string{"auth"}

	return a.buildCLICmd(ctx, args...), nil
}

func (a *CliAuthenticationProvider) GetToken(ctx context.Context) (string, error) {
	cmd, err := a.configGetAPICmd(ctx)
	if err != nil {
		return "", err
	}

	var out strings.Builder
	cmd.Stdout = &out

	err = a.runCLICmd(ctx, cmd)
	if err != nil {
		return "", err
	}

	token := out.String()
	token = strings.TrimSuffix(token, "\r")
	token = strings.TrimSuffix(token, "\n")

	if token == "" {
		return "", ErrEmptyAPIToken
	}

	return token, err
}

// ClearToken represents the `snyk config unset api` command.
func (a *CliAuthenticationProvider) ClearToken(ctx context.Context) error { // todo: unify this and get token function logic
	cmd, err := a.configUnsetAPICmd(ctx)
	if err != nil {
		return err
	}

	var out strings.Builder
	cmd.Stdout = &out

	err = a.runCLICmd(ctx, cmd)

	str := out.String()
	log.Info().Str("output", str).Msg("unset Snyk CLI API token")

	if err != nil {
		return err
	}

	return err
}

// GetToken represents the `snyk config get api` command.
func (a *CliAuthenticationProvider) configGetAPICmd(ctx context.Context) (*exec.Cmd, error) {
	log.Info().Msg("get Snyk API token")

	args := []string{"config", "get", "api"}

	return a.buildCLICmd(ctx, args...), nil
}

func (a *CliAuthenticationProvider) configUnsetAPICmd(ctx context.Context) (*exec.Cmd, error) {
	log.Info().Msg("unset Snyk CLI API token")

	// flags and other arguments should be added here (e.g. --insecure etc)
	args := []string{"config", "unset", "api"}

	return a.buildCLICmd(ctx, args...), nil
}

func (a *CliAuthenticationProvider) buildCLICmd(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, config.CurrentConfig().CliSettings().Path(), args...)

	endpoint := config.CurrentConfig().CliSettings().Endpoint
	cmd.Env = append(cmd.Env, "SNYK_API="+endpoint)

	log.Info().Str("command", cmd.String()).Interface("env", cmd.Env).Msg("running Snyk CLI command")
	return cmd
}

func (a *CliAuthenticationProvider) runCLICmd(ctx context.Context, cmd *exec.Cmd) error {
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
