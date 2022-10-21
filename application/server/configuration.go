/*
 * Copyright 2022 Snyk Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package server

import (
	"context"
	"os"
	"strconv"
	"strings"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/handler"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/application/server/lsp"
)

func WorkspaceDidChangeConfiguration(srv *jrpc2.Server) jrpc2.Handler {
	return handler.New(func(ctx context.Context, params lsp.DidChangeConfigurationParams) (bool, error) {
		log.Info().Str("method", "WorkspaceDidChangeConfiguration").Interface("params", params).Msg("RECEIVED")
		defer log.Info().Str("method", "WorkspaceDidChangeConfiguration").Interface("params", params).Msg("DONE")

		emptySettings := lsp.Settings{}
		if params.Settings != emptySettings {
			// client used settings push
			UpdateSettings(ctx, params.Settings)
			return true, nil
		}

		// client expects settings pull. E.g. VS Code uses pull model & sends empty settings when configuration is updated.
		if !config.CurrentConfig().ClientCapabilities().Workspace.Configuration {
			log.Info().Msg("Pull model for workspace configuration not supported, ignoring workspace/didChangeConfiguration notification.")
			return false, nil
		}

		configRequestParams := lsp.ConfigurationParams{
			Items: []lsp.ConfigurationItem{
				{Section: "snyk"},
			},
		}
		res, err := srv.Callback(ctx, "workspace/configuration", configRequestParams)
		if err != nil {
			return false, err
		}

		var fetchedSettings []lsp.Settings
		err = res.UnmarshalResult(&fetchedSettings)
		if err != nil {
			return false, err
		}

		if fetchedSettings[0] != emptySettings {
			UpdateSettings(ctx, fetchedSettings[0])
			return true, nil
		}

		return false, nil
	})
}

func InitializeSettings(ctx context.Context, settings lsp.Settings) {
	writeSettings(ctx, settings, true)
	updateAutoAuthentication(settings)
	updateDeviceInformation(settings)
}

func UpdateSettings(ctx context.Context, settings lsp.Settings) {
	writeSettings(ctx, settings, false)
}

func writeSettings(ctx context.Context, settings lsp.Settings, initialize bool) {
	emptySettings := lsp.Settings{}
	if settings == emptySettings {
		return
	}
	updateToken(settings.Token)
	updateProductEnablement(settings)
	updateCliConfig(settings)
	updateApiEndpoints(ctx, settings, initialize)
	updateEnvironment(settings)
	updatePath(settings)
	updateTelemetry(settings)
	updateOrganization(settings)
	manageBinariesAutomatically(settings)
}

func updateAutoAuthentication(settings lsp.Settings) {
	// Unless the field is included and set to false, auto-auth should be true by default.
	autoAuth, err := strconv.ParseBool(settings.AutomaticAuthentication)
	if err == nil {
		config.CurrentConfig().SetAutomaticAuthentication(autoAuth)
	} else {
		// When the field is omitted, set to true by default
		config.CurrentConfig().SetAutomaticAuthentication(true)
	}
}

func updateDeviceInformation(settings lsp.Settings) {
	deviceId := strings.TrimSpace(settings.DeviceId)
	if deviceId != "" {
		config.CurrentConfig().SetDeviceID(deviceId)
	}
}

func updateToken(token string) {
	// Token was sent from the client, no need to send notification
	di.Authenticator().UpdateToken(token, false)
}

func updateApiEndpoints(ctx context.Context, settings lsp.Settings, initialization bool) {
	snykApiUrl := strings.Trim(settings.Endpoint, " ")
	endpointsUpdated := config.CurrentConfig().UpdateApiEndpoints(snykApiUrl)

	if endpointsUpdated && !initialization {
		di.Authenticator().Logout(ctx)
	}
}

func updateOrganization(settings lsp.Settings) {
	org := strings.TrimSpace(settings.Organization)
	if org != "" {
		config.CurrentConfig().SetOrganization(org)
	}
}

func updateTelemetry(settings lsp.Settings) {
	parseBool, err := strconv.ParseBool(settings.SendErrorReports)
	if err != nil {
		log.Warn().Err(err).Msgf("couldn't read send error reports %s", settings.SendErrorReports)
	} else {
		config.CurrentConfig().SetErrorReportingEnabled(parseBool)
	}

	parseBool, err = strconv.ParseBool(settings.EnableTelemetry)
	if err != nil {
		log.Warn().Err(err).Msgf("couldn't read enable telemetry %s", settings.SendErrorReports)
	} else {
		config.CurrentConfig().SetTelemetryEnabled(parseBool)
		if parseBool {
			go di.Analytics().Identify()
		}
	}
}

func manageBinariesAutomatically(settings lsp.Settings) {
	parseBool, err := strconv.ParseBool(settings.ManageBinariesAutomatically)
	if err != nil {
		log.Warn().Err(err).Msgf("couldn't read manage binaries automatically %s", settings.ManageBinariesAutomatically)
	} else {
		config.CurrentConfig().SetManageBinariesAutomatically(parseBool)
	}
}

// TODO store in config, move parsing to CLI
func updatePath(settings lsp.Settings) {
	err := os.Setenv("PATH", os.Getenv("PATH")+string(os.PathSeparator)+settings.Path)
	if err != nil {
		log.Err(err).Msgf("couldn't add path %s", settings.Path)
	}
}

// TODO store in config, move parsing to CLI
func updateEnvironment(settings lsp.Settings) {
	envVars := strings.Split(settings.AdditionalEnv, ";")
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

func updateCliConfig(settings lsp.Settings) {
	var err error
	cliSettings := &config.CliSettings{}
	cliSettings.Insecure, err = strconv.ParseBool(settings.Insecure)
	if err != nil {
		log.Warn().Err(err).Msg("couldn't parse insecure setting")
	}
	cliSettings.AdditionalParameters = strings.Split(settings.AdditionalParams, " ")
	cliSettings.SetPath(settings.CliPath)

	config.CurrentConfig().SetCliSettings(cliSettings)
}

func updateProductEnablement(settings lsp.Settings) {
	parseBool, err := strconv.ParseBool(settings.ActivateSnykCode)
	if err != nil {
		log.Warn().Err(err).Msg("couldn't parse code setting")
	} else {
		config.CurrentConfig().SetSnykCodeEnabled(parseBool)
	}
	parseBool, err = strconv.ParseBool(settings.ActivateSnykOpenSource)
	if err != nil {
		log.Warn().Err(err).Msg("couldn't parse open source setting")
	} else {
		config.CurrentConfig().SetSnykOssEnabled(parseBool)
	}
	parseBool, err = strconv.ParseBool(settings.ActivateSnykIac)
	if err != nil {
		log.Warn().Err(err).Msg("couldn't parse iac setting")
	} else {
		config.CurrentConfig().SetSnykIacEnabled(parseBool)
	}
}
