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

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/internal/lsp"
	"github.com/snyk/snyk-ls/internal/observability/ux"
)

var cachedOriginalPath = ""

func workspaceDidChangeConfiguration(srv *jrpc2.Server) jrpc2.Handler {
	return handler.New(func(ctx context.Context, params lsp.DidChangeConfigurationParams) (bool, error) {
		c := config.CurrentConfig()
		c.Logger().Info().Str("method", "WorkspaceDidChangeConfiguration").Interface("params", params).Msg("RECEIVED")
		defer c.Logger().Info().Str("method", "WorkspaceDidChangeConfiguration").Interface("params", params).Msg("DONE")

		emptySettings := lsp.Settings{}
		if !reflect.DeepEqual(params.Settings, emptySettings) {
			// client used settings push
			UpdateSettings(c, params.Settings)
			return true, nil
		}

		// client expects settings pull. E.g. VS Code uses pull model & sends empty settings when configuration is updated.
		if !c.ClientCapabilities().Workspace.Configuration {
			c.Logger().Info().Msg("Pull model for workspace configuration not supported, ignoring workspace/didChangeConfiguration notification.")
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
			UpdateSettings(c, fetchedSettings[0])
			return true, nil
		}

		return false, nil
	})
}

func InitializeSettings(c *config.Config, settings lsp.Settings) {
	writeSettings(c, settings, true)
	updateAutoAuthentication(c, settings)
	updateDeviceInformation(c, settings)
	updateAutoScan(c, settings)
	c.SetClientProtocolVersion(settings.RequiredProtocolVersion)
}

func UpdateSettings(c *config.Config, settings lsp.Settings) {
	previouslyEnabledProducts := c.DisplayableIssueTypes()
	previousAutoScan := c.IsAutoScanEnabled()

	writeSettings(c, settings, false)

	// If a product was removed, clear all issues for this product
	ws := workspace.Get()
	if ws != nil {
		newSupportedProducts := c.DisplayableIssueTypes()
		for removedIssueType, wasSupported := range previouslyEnabledProducts {
			if wasSupported && !newSupportedProducts[removedIssueType] {
				ws.ClearIssuesByType(removedIssueType)
			}
		}
	}

	if c.IsAutoScanEnabled() != previousAutoScan {
		di.Analytics().ScanModeIsSelected(ux.ScanModeIsSelectedProperties{ScanningMode: settings.ScanningMode})
	}
}

func writeSettings(c *config.Config, settings lsp.Settings, initialize bool) {
	emptySettings := lsp.Settings{}
	if reflect.DeepEqual(settings, emptySettings) {
		return
	}
	updateSeverityFilter(c, settings.FilterSeverity)
	updateProductEnablement(c, settings)
	updateCliConfig(c, settings)
	updateAuthenticationMethod(c, settings)
	updateApiEndpoints(c, settings, initialize)
	updateToken(settings.Token)
	updateEnvironment(c, settings)
	updatePathFromSettings(c, settings)
	updateTelemetry(c, settings)
	updateOrganization(c, settings)
	manageBinariesAutomatically(c, settings)
	updateTrustedFolders(c, settings)
	updateSnykCodeSecurity(c, settings)
	updateSnykCodeQuality(c, settings)
	updateRuntimeInfo(c, settings)
	updateAutoScan(c, settings)
	updateSnykLearnCodeActions(c, settings)
	updateSnykOSSQuickFixCodeActions(c, settings)
}

func updateAuthenticationMethod(c *config.Config, settings lsp.Settings) {
	if lsp.EmptyAuthenticationMethod == settings.AuthenticationMethod {
		return
	}

	c.SetAuthenticationMethod(settings.AuthenticationMethod)
	di.AuthenticationService().ConfigureProviders(c)
}

func updateRuntimeInfo(c *config.Config, settings lsp.Settings) {
	c.SetOsArch(settings.OsArch)
	c.SetOsPlatform(settings.OsPlatform)
	c.SetRuntimeVersion(settings.RuntimeVersion)
	c.SetRuntimeName(settings.RuntimeName)
}

func updateTrustedFolders(c *config.Config, settings lsp.Settings) {
	trustedFoldersFeatureEnabled, err := strconv.ParseBool(settings.EnableTrustedFoldersFeature)
	if err == nil {
		c.SetTrustedFolderFeatureEnabled(trustedFoldersFeatureEnabled)
	} else {
		c.SetTrustedFolderFeatureEnabled(true)
	}

	if settings.TrustedFolders != nil {
		c.SetTrustedFolders(settings.TrustedFolders)
	}
}

func updateAutoAuthentication(c *config.Config, settings lsp.Settings) {
	// Unless the field is included and set to false, auto-auth should be true by default.
	autoAuth, err := strconv.ParseBool(settings.AutomaticAuthentication)
	if err == nil {
		c.SetAutomaticAuthentication(autoAuth)
	} else {
		// When the field is omitted, set to true by default
		c.SetAutomaticAuthentication(true)
	}
}

func updateDeviceInformation(c *config.Config, settings lsp.Settings) {
	deviceId := strings.TrimSpace(settings.DeviceId)
	if deviceId != "" {
		c.SetDeviceID(deviceId)
	}
}

func updateAutoScan(c *config.Config, settings lsp.Settings) {
	// Auto scan true by default unless the AutoScan value in the settings is not missing & false
	autoScan := true
	if settings.ScanningMode == "manual" {
		autoScan = false
	}

	c.SetAutomaticScanning(autoScan)
}

func updateSnykLearnCodeActions(c *config.Config, settings lsp.Settings) {
	enable := true
	if settings.EnableSnykLearnCodeActions == "false" {
		enable = false
	}

	c.SetSnykLearnCodeActionsEnabled(enable)
}

func updateSnykOSSQuickFixCodeActions(c *config.Config, settings lsp.Settings) {
	enable := true
	if settings.EnableSnykOSSQuickFixCodeActions == "false" {
		enable = false
	}

	c.SetSnykOSSQuickFixCodeActionsEnabled(enable)
}

func updateToken(token string) {
	// Token was sent from the client, no need to send notification
	di.AuthenticationService().UpdateCredentials(token, false)
}

func updateApiEndpoints(c *config.Config, settings lsp.Settings, initialization bool) {
	snykApiUrl := strings.Trim(settings.Endpoint, " ")
	endpointsUpdated := c.UpdateApiEndpoints(snykApiUrl)

	if endpointsUpdated && !initialization {
		di.AuthenticationService().Logout(context.Background())
		workspace.Get().Clear()
	}

	// a custom set snyk code api (e.g. for testing) always overwrites automatic config
	if settings.SnykCodeApi != "" {
		c.SetSnykCodeApi(settings.SnykCodeApi)
	}
}

func updateOrganization(c *config.Config, settings lsp.Settings) {
	org := strings.TrimSpace(settings.Organization)
	if org != "" {
		c.SetOrganization(org)
	}
}

func updateTelemetry(c *config.Config, settings lsp.Settings) {
	parseBool, err := strconv.ParseBool(settings.SendErrorReports)
	if err != nil {
		c.Logger().Debug().Msgf("couldn't read send error reports %s", settings.SendErrorReports)
	} else {
		c.SetErrorReportingEnabled(parseBool)
	}

	parseBool, err = strconv.ParseBool(settings.EnableTelemetry)
	if err != nil {
		c.Logger().Debug().Msgf("couldn't read enable telemetry %s", settings.SendErrorReports)
	} else {
		c.SetTelemetryEnabled(parseBool)
		if parseBool {
			go di.Analytics().Identify()
		}
	}
}

func manageBinariesAutomatically(c *config.Config, settings lsp.Settings) {
	parseBool, err := strconv.ParseBool(settings.ManageBinariesAutomatically)
	if err != nil {
		c.Logger().Debug().Msgf("couldn't read manage binaries automatically %s", settings.ManageBinariesAutomatically)
	} else {
		c.SetManageBinariesAutomatically(parseBool)
	}
}

func updateSnykCodeSecurity(c *config.Config, settings lsp.Settings) {
	parseBool, err := strconv.ParseBool(settings.ActivateSnykCodeSecurity)
	if err != nil {
		c.Logger().Debug().Msgf("couldn't read IsSnykCodeSecurityEnabled %s", settings.ActivateSnykCodeSecurity)
	} else {
		c.EnableSnykCodeSecurity(parseBool)
	}
}

func updateSnykCodeQuality(c *config.Config, settings lsp.Settings) {
	parseBool, err := strconv.ParseBool(settings.ActivateSnykCodeQuality)
	if err != nil {
		c.Logger().Debug().Msgf("couldn't read IsSnykCodeQualityEnabled %s", settings.ActivateSnykCodeQuality)
	} else {
		c.EnableSnykCodeQuality(parseBool)
	}
}

// TODO store in config, move parsing to CLI
func updatePathFromSettings(c *config.Config, settings lsp.Settings) {
	// when changing the path from settings, we cache the original path first, to be able to restore it later
	if len(cachedOriginalPath) == 0 {
		cachedOriginalPath = os.Getenv("PATH")
	}

	if len(settings.Path) > 0 {
		_ = os.Unsetenv("Path") // unset the path first to work around issues on Windows OS, where PATH can be Path
		err := os.Setenv("PATH", settings.Path+string(os.PathListSeparator)+cachedOriginalPath)
		c.Logger().Info().Str("method", "updatePathFromSettings").Msgf("added configured path to PATH Environment Variable '%s'", os.Getenv("PATH"))
		if err != nil {
			c.Logger().Err(err).Str("method", "updatePathFromSettings").Msgf("couldn't add path %s", settings.Path)
		}
	} else {
		_ = os.Setenv("PATH", cachedOriginalPath)
		c.Logger().Info().Str("method", "updatePathFromSettings").Msgf("restore initial path '%s'", os.Getenv("PATH"))
	}
}

// TODO store in config, move parsing to CLI
func updateEnvironment(c *config.Config, settings lsp.Settings) {
	envVars := strings.Split(settings.AdditionalEnv, ";")
	for _, envVar := range envVars {
		v := strings.Split(envVar, "=")
		if len(v) != 2 {
			continue
		}
		err := os.Setenv(v[0], v[1])
		if err != nil {
			c.Logger().Err(err).Msgf("couldn't set env variable %s", envVar)
		}
	}
}

func updateCliConfig(c *config.Config, settings lsp.Settings) {
	var err error
	cliSettings := &config.CliSettings{C: c}
	cliSettings.Insecure, err = strconv.ParseBool(settings.Insecure)
	if err != nil {
		c.Logger().Debug().Msg("couldn't parse insecure setting")
	}
	cliSettings.AdditionalOssParameters = strings.Split(settings.AdditionalParams, " ")
	cliSettings.SetPath(strings.TrimSpace(settings.CliPath))
	currentConfig := c
	conf := currentConfig.Engine().GetConfiguration()
	conf.Set(configuration.INSECURE_HTTPS, cliSettings.Insecure)
	currentConfig.SetCliSettings(cliSettings)
}

func updateProductEnablement(c *config.Config, settings lsp.Settings) {
	parseBool, err := strconv.ParseBool(settings.ActivateSnykCode)
	if err != nil {
		c.Logger().Debug().Msg("couldn't parse code setting")
	} else {
		c.SetSnykCodeEnabled(parseBool)
		c.EnableSnykCodeQuality(parseBool)
		c.EnableSnykCodeSecurity(parseBool)
	}
	parseBool, err = strconv.ParseBool(settings.ActivateSnykOpenSource)
	if err != nil {
		c.Logger().Debug().Msg("couldn't parse open source setting")
	} else {
		c.SetSnykOssEnabled(parseBool)
	}
	parseBool, err = strconv.ParseBool(settings.ActivateSnykIac)
	if err != nil {
		c.Logger().Debug().Msg("couldn't parse iac setting")
	} else {
		c.SetSnykIacEnabled(parseBool)
	}
}

func updateSeverityFilter(c *config.Config, s lsp.SeverityFilter) {
	c.Logger().Debug().Str("method", "updateSeverityFilter").Interface("severityFilter", s).Msg("Updating severity filter:")
	modified := c.SetSeverityFilter(s)

	if modified {
		ws := workspace.Get()
		if ws == nil {
			return
		}

		for _, folder := range ws.Folders() {
			folder.FilterAndPublishDiagnostics(nil)
		}
	}
}
