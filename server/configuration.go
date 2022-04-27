package server

import (
	"context"
	"os"
	"strconv"
	"strings"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/handler"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/lsp"
)

func WorkspaceDidChangeConfiguration() jrpc2.Handler {
	return handler.New(func(ctx context.Context, params lsp.DidChangeConfigurationParams) (interface{}, error) {
		var err error
		environment.CurrentEnabledProducts.Code, err = strconv.ParseBool(params.Settings.ActivateSnykCode)
		if err != nil {
			log.Err(err).Msg("couldn't parse code setting")
		}
		environment.CurrentEnabledProducts.OpenSource, err = strconv.ParseBool(params.Settings.ActivateSnykOpenSource)
		if err != nil {
			log.Err(err).Msg("couldn't parse open source setting")
		}
		environment.CurrentEnabledProducts.Iac, err = strconv.ParseBool(params.Settings.ActivateSnykIac)
		if err != nil {
			log.Err(err).Msg("couldn't parse iac setting")
		}
		cli.CurrentSettings.Insecure, err = strconv.ParseBool(params.Settings.Insecure)
		if err != nil {
			log.Err(err).Msg("couldn't parse insecure setting")
		}

		cli.CurrentSettings.Endpoint = params.Settings.Endpoint

		cli.CurrentSettings.AdditionalParameters = strings.Split(params.Settings.AdditionalParams, " ")
		envVars := strings.Split(params.Settings.AdditionalEnv, ";")
		for _, envVar := range envVars {
			v := strings.Split(envVar, "=")
			err = os.Setenv(v[0], v[1])
			if err != nil {
				log.Err(err).Msgf("couldn't set env variable %s", envVar)
			}
		}
		err = os.Setenv("PATH", os.Getenv("PATH")+string(os.PathSeparator)+params.Settings.Path)
		if err != nil {
			if err != nil {
				log.Err(err).Msgf("couldn't add path %s", params.Settings.Path)
			}
		}
		return nil, nil
	})
}
