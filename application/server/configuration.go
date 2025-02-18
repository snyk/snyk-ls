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

	"github.com/snyk/snyk-ls/internal/storedconfig"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/handler"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/internal/types"
)

var cachedOriginalPath = ""

func workspaceDidChangeConfiguration(srv *jrpc2.Server) jrpc2.Handler {
	return handler.New(func(ctx context.Context, params types.DidChangeConfigurationParams) (bool, error) {
		c := config.CurrentConfig()
		c.Logger().Info().Str("method", "WorkspaceDidChangeConfiguration").Interface("params", params).Msg("RECEIVED")
		defer c.Logger().Info().Str("method", "WorkspaceDidChangeConfiguration").Interface("params", params).Msg("DONE")

		emptySettings := types.Settings{}
		if !reflect.DeepEqual(params.Settings, emptySettings) {
			// client used settings push
			UpdateSettings(c, params.Settings)
			return true, nil
		}

		// client expects settings pull. E.g. VS Code uses pull model & sends empty settings when configuration is updated.
		if !c.ClientCapabilities().Workspace.Configuration {
			c.Logger().Debug().Msg("Pull model for workspace configuration not supported, ignoring workspace/didChangeConfiguration notification.")
			return false, nil
		}

		configRequestParams := types.ConfigurationParams{
			Items: []types.ConfigurationItem{
				{Section: "snyk"},
			},
		}
		res, err := srv.Callback(ctx, "workspace/configuration", configRequestParams)
		if err != nil {
			return false, err
		}

		var fetchedSettings []types.Settings
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

func InitializeSettings(c *config.Config, settings types.Settings) {
	writeSettings(c, settings, true)
	updateAutoAuthentication(c, settings)
	updateDeviceInformation(c, settings)
	updateAutoScan(c, settings)
	c.SetClientProtocolVersion(settings.RequiredProtocolVersion)
}

func UpdateSettings(c *config.Config, settings types.Settings) {
	previouslyEnabledProducts := c.DisplayableIssueTypes()
	writeSettings(c, settings, false)

	// If a product was removed, clear all issues for this product
	ws := c.Workspace()
	if ws != nil {
		newSupportedProducts := c.DisplayableIssueTypes()
		for removedIssueType, wasSupported := range previouslyEnabledProducts {
			if wasSupported && !newSupportedProducts[removedIssueType] {
				ws.ClearIssuesByType(removedIssueType)
			}
		}
	}
}

func writeSettings(c *config.Config, settings types.Settings, initialize bool) {
	emptySettings := types.Settings{}
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
	updateErrorReporting(c, settings)
	updateOrganization(c, settings)
	manageBinariesAutomatically(c, settings)
	updateTrustedFolders(c, settings)
	updateSnykCodeSecurity(c, settings)
	updateSnykCodeQuality(c, settings)
	updateRuntimeInfo(c, settings)
	updateAutoScan(c, settings)
	updateSnykLearnCodeActions(c, settings)
	updateSnykOSSQuickFixCodeActions(c, settings)
	updateSnykOpenBrowserCodeActions(c, settings)
	updateDeltaFindings(c, settings)
	updateFolderConfig(c, settings)
	updateHoverVerbosity(c, settings)
	updateFormat(c, settings)
}

func updateFormat(c *config.Config, settings types.Settings) {
	if settings.OutputFormat != nil {
		c.SetFormat(*settings.OutputFormat)
	}
}

func updateHoverVerbosity(c *config.Config, settings types.Settings) {
	if settings.HoverVerbosity != nil {
		c.SetHoverVerbosity(*settings.HoverVerbosity)
	}
}

func updateSnykOpenBrowserCodeActions(c *config.Config, settings types.Settings) {
	enable := false
	if settings.EnableSnykOpenBrowserActions == "true" {
		enable = true
	}

	c.SetSnykOpenBrowserActionsEnabled(enable)
}

func updateFolderConfig(c *config.Config, settings types.Settings) {
	err := storedconfig.UpdateFolderConfigs(c.Engine().GetConfiguration(), settings.FolderConfigs)
	if err != nil {
		c.Logger().Err(err).Msg("couldn't update folder configs")
	}
}

func updateAuthenticationMethod(c *config.Config, settings types.Settings) {
	if types.EmptyAuthenticationMethod == settings.AuthenticationMethod {
		return
	}

	c.SetAuthenticationMethod(settings.AuthenticationMethod)
	di.AuthenticationService().ConfigureProviders(c)
}

func updateRuntimeInfo(c *config.Config, settings types.Settings) {
	c.SetOsArch(settings.OsArch)
	c.SetOsPlatform(settings.OsPlatform)
	c.SetRuntimeVersion(settings.RuntimeVersion)
	c.SetRuntimeName(settings.RuntimeName)
}

func updateTrustedFolders(c *config.Config, settings types.Settings) {
	trustedFoldersFeatureEnabled, err := strconv.ParseBool(settings.EnableTrustedFoldersFeature)
	if err == nil {
		c.SetTrustedFolderFeatureEnabled(trustedFoldersFeatureEnabled)
	} else {
		c.SetTrustedFolderFeatureEnabled(true)
	}

	if settings.TrustedFolders != nil {
		var trustedFolders []types.FilePath
		for _, folder := range settings.TrustedFolders {
			trustedFolders = append(trustedFolders, types.FilePath(folder))
		}
		c.SetTrustedFolders(trustedFolders)
	}
}

func updateAutoAuthentication(c *config.Config, settings types.Settings) {
	// Unless the field is included and set to false, auto-auth should be true by default.
	autoAuth, err := strconv.ParseBool(settings.AutomaticAuthentication)
	if err == nil {
		c.SetAutomaticAuthentication(autoAuth)
	} else {
		// When the field is omitted, set to true by default
		c.SetAutomaticAuthentication(true)
	}
}

func updateDeviceInformation(c *config.Config, settings types.Settings) {
	deviceId := strings.TrimSpace(settings.DeviceId)
	if deviceId != "" {
		c.SetDeviceID(deviceId)
	}
}

func updateAutoScan(c *config.Config, settings types.Settings) {
	// Auto scan true by default unless the AutoScan value in the settings is not missing & false
	autoScan := true
	if settings.ScanningMode == "manual" {
		autoScan = false
	}

	c.SetAutomaticScanning(autoScan)
}

func updateSnykLearnCodeActions(c *config.Config, settings types.Settings) {
	enable := true
	if settings.EnableSnykLearnCodeActions == "false" {
		enable = false
	}

	c.SetSnykLearnCodeActionsEnabled(enable)
}

func updateSnykOSSQuickFixCodeActions(c *config.Config, settings types.Settings) {
	enable := true
	if settings.EnableSnykOSSQuickFixCodeActions == "false" {
		enable = false
	}

	c.SetSnykOSSQuickFixCodeActionsEnabled(enable)
}

func updateDeltaFindings(c *config.Config, settings types.Settings) {
	enable := true
	if settings.EnableDeltaFindings == "" || settings.EnableDeltaFindings == "false" {
		enable = false
	}

	modified := c.SetDeltaFindingsEnabled(enable)
	if modified {
		sendWorkspaceConfigChanged(c)
	}
}

func updateToken(token string) {
	// Token was sent from the client, no need to send notification
	di.AuthenticationService().UpdateCredentials(token, false, false)
}

func updateApiEndpoints(c *config.Config, settings types.Settings, initialization bool) {
	snykApiUrl := strings.Trim(settings.Endpoint, " ")
	endpointsUpdated := c.UpdateApiEndpoints(snykApiUrl)

	if endpointsUpdated && !initialization {
		authService := di.AuthenticationService()
		authService.Logout(context.Background())
		authService.ConfigureProviders(c)
		c.Workspace().Clear()
	}

	// a custom set snyk code api (e.g. for testing) always overwrites automatic config
	if settings.SnykCodeApi != "" {
		c.SetSnykCodeApi(settings.SnykCodeApi)
	}
}

func updateOrganization(c *config.Config, settings types.Settings) {
	org := strings.TrimSpace(settings.Organization)
	if org != "" {
		c.SetOrganization(org)
	}
}

func updateErrorReporting(c *config.Config, settings types.Settings) {
	parseBool, err := strconv.ParseBool(settings.SendErrorReports)
	if err != nil {
		c.Logger().Debug().Msgf("couldn't read send error reports %s", settings.SendErrorReports)
	} else {
		c.SetErrorReportingEnabled(parseBool)
	}
}

func manageBinariesAutomatically(c *config.Config, settings types.Settings) {
	parseBool, err := strconv.ParseBool(settings.ManageBinariesAutomatically)
	if err != nil {
		c.Logger().Debug().Msgf("couldn't read manage binaries automatically %s", settings.ManageBinariesAutomatically)
	} else {
		c.SetManageBinariesAutomatically(parseBool)
	}
}

func updateSnykCodeSecurity(c *config.Config, settings types.Settings) {
	parseBool, err := strconv.ParseBool(settings.ActivateSnykCodeSecurity)
	if err != nil {
		c.Logger().Debug().Msgf("couldn't read IsSnykCodeSecurityEnabled %s", settings.ActivateSnykCodeSecurity)
	} else {
		c.EnableSnykCodeSecurity(parseBool)
	}
}

func updateSnykCodeQuality(c *config.Config, settings types.Settings) {
	parseBool, err := strconv.ParseBool(settings.ActivateSnykCodeQuality)
	if err != nil {
		c.Logger().Debug().Msgf("couldn't read IsSnykCodeQualityEnabled %s", settings.ActivateSnykCodeQuality)
	} else {
		c.EnableSnykCodeQuality(parseBool)
	}
}

// TODO store in config, move parsing to CLI
func updatePathFromSettings(c *config.Config, settings types.Settings) {
	// when changing the path from settings, we cache the original path first, to be able to restore it later
	if len(cachedOriginalPath) == 0 {
		cachedOriginalPath = os.Getenv("PATH")
	}

	if len(settings.Path) > 0 {
		_ = os.Unsetenv("Path") // unset the path first to work around issues on Windows OS, where PATH can be Path
		err := os.Setenv("PATH", settings.Path+string(os.PathListSeparator)+cachedOriginalPath)
		c.Logger().Debug().Str("method", "updatePathFromSettings").Msgf("added configured path to PATH Environment Variable '%s'", os.Getenv("PATH"))
		if err != nil {
			c.Logger().Err(err).Str("method", "updatePathFromSettings").Msgf("couldn't add path %s", settings.Path)
		}
	} else {
		_ = os.Setenv("PATH", cachedOriginalPath)
		c.Logger().Debug().Str("method", "updatePathFromSettings").Msgf("restore initial path '%s'", os.Getenv("PATH"))
	}
}

// TODO store in config, move parsing to CLI
func updateEnvironment(c *config.Config, settings types.Settings) {
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

func updateCliConfig(c *config.Config, settings types.Settings) {
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

func updateProductEnablement(c *config.Config, settings types.Settings) {
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

func updateSeverityFilter(c *config.Config, s types.SeverityFilter) {
	c.Logger().Debug().Str("method", "updateSeverityFilter").Interface("severityFilter", s).Msg("Updating severity filter:")
	modified := c.SetSeverityFilter(s)

	if modified {
		sendWorkspaceConfigChanged(c)
	}
}

func sendWorkspaceConfigChanged(c *config.Config) {
	ws := c.Workspace()
	if ws == nil {
		return
	}
	go ws.HandleConfigChange()
}
