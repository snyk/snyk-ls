/*
 * © 2022 Snyk Limited All rights reserved.
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
	"reflect"
	"strconv"
	"strings"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/handler"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/observability/ux"
)

func WorkspaceDidChangeConfiguration(srv *jrpc2.Server) jrpc2.Handler {
	return handler.New(func(ctx context.Context, params lsp.DidChangeConfigurationParams) (bool, error) {
		log.Info().Str("method", "WorkspaceDidChangeConfiguration").Interface("params", params).Msg("RECEIVED")
		defer log.Info().Str("method", "WorkspaceDidChangeConfiguration").Interface("params", params).Msg("DONE")

		emptySettings := lsp.Settings{}
		if !reflect.DeepEqual(params.Settings, emptySettings) {
			// client used settings push
			UpdateSettings(params.Settings)
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

		if !reflect.DeepEqual(fetchedSettings[0], emptySettings) {
			UpdateSettings(fetchedSettings[0])
			return true, nil
		}

		return false, nil
	})
}

func InitializeSettings(settings lsp.Settings) {
	writeSettings(settings, true)
	updateAutoAuthentication(settings)
	updateDeviceInformation(settings)
	updateAutoScan(settings)
}

func UpdateSettings(settings lsp.Settings) {
	currentConfig := config.CurrentConfig()
	previouslySupportedProducts := currentConfig.GetDisplayableIssueTypes()
	previousAutoScan := currentConfig.IsAutoScanEnabled()

	writeSettings(settings, false)

	// If a product was removed, clear all issues for this product
	ws := workspace.Get()
	if ws != nil {
		newSupportedProducts := currentConfig.GetDisplayableIssueTypes()
		for removedIssueType, wasSupported := range previouslySupportedProducts {
			if wasSupported && !newSupportedProducts[removedIssueType] {
				ws.ClearIssuesByType(removedIssueType)
			}
		}
	}

	if currentConfig.IsAutoScanEnabled() != previousAutoScan {
		di.Analytics().ScanModeIsSelected(ux.ScanModeIsSelectedProperties{ScanningMode: settings.ScanningMode})
	}
}

func writeSettings(settings lsp.Settings, initialize bool) {
	emptySettings := lsp.Settings{}
	if reflect.DeepEqual(settings, emptySettings) {
		return
	}
	updateSeverityFilter(settings.FilterSeverity)
	updateToken(settings.Token)
	updateProductEnablement(settings)
	updateCliConfig(settings)
	updateApiEndpoints(settings, initialize)
	updateEnvironment(settings)
	updatePath(settings)
	updateTelemetry(settings)
	updateOrganization(settings)
	manageBinariesAutomatically(settings)
	updateTrustedFolders(settings)
	updateSnykCodeSecurity(settings)
	updateSnykCodeQuality(settings)
	updateRuntimeInfo(settings)
	updateAutoScan(settings)
}

func updateRuntimeInfo(settings lsp.Settings) {
	c := config.CurrentConfig()
	c.SetOsArch(settings.OsArch)
	c.SetOsPlatform(settings.OsPlatform)
	c.SetRuntimeVersion(settings.RuntimeVersion)
	c.SetRuntimeName(settings.RuntimeName)
}

func updateTrustedFolders(settings lsp.Settings) {
	trustedFoldersFeatureEnabled, err := strconv.ParseBool(settings.EnableTrustedFoldersFeature)
	if err == nil {
		config.CurrentConfig().SetTrustedFolderFeatureEnabled(trustedFoldersFeatureEnabled)
	} else {
		config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)
	}

	if settings.TrustedFolders != nil {
		config.CurrentConfig().SetTrustedFolders(settings.TrustedFolders)
	}
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

func updateAutoScan(settings lsp.Settings) {
	// Auto scan true by default unless the AutoScan value in the settings is not missing & false
	autoScan := true
	if settings.ScanningMode == "manual" {
		autoScan = false
	}

	config.CurrentConfig().SetAutomaticScanning(autoScan)
}

func updateToken(token string) {
	// Token was sent from the client, no need to send notification
	di.Authenticator().UpdateToken(token, false)
}

func updateApiEndpoints(settings lsp.Settings, initialization bool) {
	snykApiUrl := strings.Trim(settings.Endpoint, " ")
	endpointsUpdated := config.CurrentConfig().UpdateApiEndpoints(snykApiUrl)

	if endpointsUpdated && !initialization {
		di.Authenticator().Logout(context.Background())
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

func updateSnykCodeSecurity(settings lsp.Settings) {
	parseBool, err := strconv.ParseBool(settings.ActivateSnykCodeSecurity)
	if err != nil {
		log.Warn().Err(err).Msgf("couldn't read IsSnykCodeSecurityEnabled %s", settings.ActivateSnykCodeSecurity)
	} else {
		config.CurrentConfig().EnableSnykCodeSecurity(parseBool)
	}
}

func updateSnykCodeQuality(settings lsp.Settings) {
	parseBool, err := strconv.ParseBool(settings.ActivateSnykCodeQuality)
	if err != nil {
		log.Warn().Err(err).Msgf("couldn't read IsSnykCodeQualityEnabled %s", settings.ActivateSnykCodeQuality)
	} else {
		config.CurrentConfig().EnableSnykCodeQuality(parseBool)
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
	cliSettings.AdditionalOssParameters = strings.Split(settings.AdditionalParams, " ")
	cliSettings.SetPath(settings.CliPath)

	config.CurrentConfig().SetCliSettings(cliSettings)
}

func updateProductEnablement(settings lsp.Settings) {
	parseBool, err := strconv.ParseBool(settings.ActivateSnykCode)
	currentConfig := config.CurrentConfig()
	if err != nil {
		log.Warn().Err(err).Msg("couldn't parse code setting")
	} else {
		currentConfig.SetSnykCodeEnabled(parseBool)
		currentConfig.EnableSnykCodeQuality(parseBool)
		currentConfig.EnableSnykCodeSecurity(parseBool)
	}
	parseBool, err = strconv.ParseBool(settings.ActivateSnykOpenSource)
	if err != nil {
		log.Warn().Err(err).Msg("couldn't parse open source setting")
	} else {
		currentConfig.SetSnykOssEnabled(parseBool)
	}
	parseBool, err = strconv.ParseBool(settings.ActivateSnykIac)
	if err != nil {
		log.Warn().Err(err).Msg("couldn't parse iac setting")
	} else {
		currentConfig.SetSnykIacEnabled(parseBool)
	}
}

func updateSeverityFilter(s lsp.SeverityFilter) {
	log.Debug().Str("method", "updateSeverityFilter").Msgf("Updating severity filter: %v", s)
	modified := config.CurrentConfig().SetSeverityFilter(s)

	if modified {
		ws := workspace.Get()
		if ws == nil {
			return
		}

		for _, folder := range ws.Folders() {
			folder.FilterAndPublishCachedDiagnostics()
		}
	}
}
