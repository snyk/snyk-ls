package server

import (
	"context"
	"os"
	"strconv"
	"strings"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/handler"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/lsp"
)

func WorkspaceDidChangeConfiguration() jrpc2.Handler {
	return handler.New(func(ctx context.Context, params lsp.DidChangeConfigurationParams) (interface{}, error) {
		log.Info().Str("method", "WorkspaceDidChangeConfiguration").Interface("params", params).Msg("RECEIVED")
		defer log.Info().Str("method", "WorkspaceDidChangeConfiguration").Interface("params", params).Msg("DONE")
		updateProductEnablement(params)
		updateCliConfig(params)
		updateEnvironment(params)
		updatePath(params)
		updateTelemetry(params)
		updateOrganization(params)
		return nil, nil
	})
}

func updateOrganization(params lsp.DidChangeConfigurationParams) {
	org := strings.TrimSpace(params.Settings.Organization)
	if org != "" {
		config.CurrentConfig().SetOrganization(org)
	}
}

func updateTelemetry(params lsp.DidChangeConfigurationParams) {
	parseBool, err := strconv.ParseBool(params.Settings.SendErrorReports)
	if err != nil {
		log.Err(err).Msgf("couldn't read send error reports %s", params.Settings.SendErrorReports)
	}
	config.CurrentConfig().SetErrorReportingEnabled(parseBool)

	parseBool, err = strconv.ParseBool(params.Settings.EnableTelemetry)
	if err != nil {
		log.Err(err).Msgf("couldn't read send error reports %s", params.Settings.SendErrorReports)
	}
	config.CurrentConfig().SetTelemetryEnabled(parseBool)
}

// TODO store in config, move parsing to CLI
func updatePath(params lsp.DidChangeConfigurationParams) {
	err := os.Setenv("PATH", os.Getenv("PATH")+string(os.PathSeparator)+params.Settings.Path)
	if err != nil {
		log.Err(err).Msgf("couldn't add path %s", params.Settings.Path)
	}
}

// TODO store in config, move parsing to CLI
func updateEnvironment(params lsp.DidChangeConfigurationParams) {
	envVars := strings.Split(params.Settings.AdditionalEnv, ";")
	for _, envVar := range envVars {
		v := strings.Split(envVar, "=")
		if len(v) != 2 {
			continue
		}
		err := os.Setenv(v[0], v[1])
		if err != nil {
			log.Err(err).Msgf("couldn't set env variable %s", envVar)
		}
	}
}

func updateCliConfig(params lsp.DidChangeConfigurationParams) {
	var err error
	settings := config.CliSettings{}
	settings.Insecure, err = strconv.ParseBool(params.Settings.Insecure)
	if err != nil {
		log.Err(err).Msg("couldn't parse insecure setting")
	}
	settings.Endpoint = strings.Trim(params.Settings.Endpoint, " ")
	settings.AdditionalParameters = strings.Split(params.Settings.AdditionalParams, " ")
	config.CurrentConfig().SetCliSettings(settings)
}

func updateProductEnablement(params lsp.DidChangeConfigurationParams) {
	parseBool, err := strconv.ParseBool(params.Settings.ActivateSnykCode)
	if err != nil {
		log.Err(err).Msg("couldn't parse code setting")
	} else {
		config.CurrentConfig().SetSnykCodeEnabled(parseBool)
	}
	parseBool, err = strconv.ParseBool(params.Settings.ActivateSnykOpenSource)
	if err != nil {
		log.Err(err).Msg("couldn't parse open source setting")
	} else {
		config.CurrentConfig().SetSnykOssEnabled(parseBool)
	}
	parseBool, err = strconv.ParseBool(params.Settings.ActivateSnykIac)
	if err != nil {
		log.Err(err).Msg("couldn't parse iac setting")
	} else {
		config.CurrentConfig().SetSnykIacEnabled(parseBool)
	}
}
