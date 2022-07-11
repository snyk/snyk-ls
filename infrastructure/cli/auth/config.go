package auth

import (
	"context"
	"errors"
	"os/exec"
	"strings"

	"github.com/rs/zerolog/log"
)

var ErrEmptyAPIToken = errors.New("snyk-cli: api token is empty")

// GetToken represents the `snyk config get api` command.
func GetToken(ctx context.Context) (string, error) {
	cmd, err := configGetAPICmd(ctx)
	if err != nil {
		return "", err
	}

	var out strings.Builder
	cmd.Stdout = &out

	err = runCLICmd(ctx, cmd)
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

func configGetAPICmd(ctx context.Context) (*exec.Cmd, error) {
	log.Info().Msg("get Snyk API token")

	args := []string{"config", "get", "api"}

	return buildCLICmd(ctx, args...), nil
}
