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
	"github.com/rs/zerolog"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/infrastructure/analytics"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/types"
)

func workspaceDidChangeConfiguration(c *config.Config, srv *jrpc2.Server) jrpc2.Handler {
	return handler.New(func(ctx context.Context, params types.DidChangeConfigurationParams) (bool, error) {
		// we don't log the received config, as it could contain credentials that are not yet filtered.
		// it should be enough to log once we leave the handler
		defer c.Logger().Info().Str("method", "WorkspaceDidChangeConfiguration").Interface("params", params).Msg("DONE")

		emptySettings := types.Settings{}
		if !reflect.DeepEqual(params.Settings, emptySettings) {
			// client used settings push
			UpdateSettings(c, params.Settings, "user", true)
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
			UpdateSettings(c, fetchedSettings[0], "user", true)
			return true, nil
		}

		return false, nil
	})
}

func InitializeSettings(c *config.Config, settings types.Settings) {
	writeSettings(c, settings, true, "", false)
	updateAutoAuthentication(c, settings)
	updateDeviceInformation(c, settings)
	updateAutoScan(c, settings, "")
	c.SetClientProtocolVersion(settings.RequiredProtocolVersion)
}

func UpdateSettings(c *config.Config, settings types.Settings, triggerSource string, sendAnalytics bool) {
	previouslyEnabledProducts := c.DisplayableIssueTypes()
	writeSettings(c, settings, false, triggerSource, sendAnalytics)

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

func writeSettings(c *config.Config, settings types.Settings, initialize bool, triggerSource string, sendAnalytics bool) {
	c.Engine().GetConfiguration().ClearCache()

	emptySettings := types.Settings{}
	if reflect.DeepEqual(settings, emptySettings) {
		return
	}
	updateSeverityFilter(c, settings.FilterSeverity, triggerSource)
	updateIssueViewOptions(c, settings.IssueViewOptions, triggerSource)
	updateProductEnablement(c, settings, triggerSource, sendAnalytics)
	updateCliConfig(c, settings)
	updateApiEndpoints(c, settings, initialize, triggerSource) // Must be called before token is set, as it may trigger a logout which clears the token.
	updateToken(settings.Token)                                // Must be called before the Authentication method is set, as the latter checks the token.
	updateAuthenticationMethod(c, settings, triggerSource)
	updateEnvironment(c, settings)
	updatePathFromSettings(c, settings, initialize)
	updateErrorReporting(c, settings, triggerSource)
	updateOrganization(c, settings, triggerSource, sendAnalytics)
	manageBinariesAutomatically(c, settings, triggerSource)
	updateTrustedFolders(c, settings, triggerSource)
	updateSnykCodeSecurity(c, settings)
	updateRuntimeInfo(c, settings)
	updateAutoScan(c, settings, triggerSource)
	updateSnykLearnCodeActions(c, settings, triggerSource)
	updateSnykOSSQuickFixCodeActions(c, settings, triggerSource)
	updateSnykOpenBrowserCodeActions(c, settings, triggerSource)
	updateDeltaFindings(c, settings, triggerSource)
	updateFolderConfig(c, settings, c.Logger())
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

func updateSnykOpenBrowserCodeActions(c *config.Config, settings types.Settings, triggerSource string) {
	enable := false
	if settings.EnableSnykOpenBrowserActions == "true" {
		enable = true
	}

	// TODO: Add getter method for SnykOpenBrowserActionsEnabled to enable analytics
	c.SetSnykOpenBrowserActionsEnabled(enable)
}

func updateFolderConfig(c *config.Config, settings types.Settings, logger *zerolog.Logger) {
	notifier := di.Notifier()
	var folderConfigs []types.FolderConfig
	folderConfigsMayHaveChanged := false
	for _, folderConfig := range settings.FolderConfigs {
		path := folderConfig.FolderPath

		storedConfig, err2 := storedconfig.GetOrCreateFolderConfig(c.Engine().GetConfiguration(), path, logger)
		if err2 != nil {
			logger.Err(err2).Msg("unable to load stored config")
			return
		}

		// Folder config might be new or changed, so (re)resolve the org before saving it.
		// We should also check that the folder's org is still valid if the globally set org has changed.
		// Also, if the config hasn't been migrated yet, we need to perform the initial migration.
		needsMigration := !storedConfig.OrgMigratedFromGlobalConfig
		orgSettingsChanged := !folderConfigsOrgSettingsEqual(folderConfig, storedConfig)

		if needsMigration || orgSettingsChanged {
			updateFolderConfigOrg(c, notifier, storedConfig, &folderConfig)
			folderConfigsMayHaveChanged = true
		}

		folderConfigs = append(folderConfigs, folderConfig)
	}

	if folderConfigsMayHaveChanged {
		folderConfigsParam := types.FolderConfigsParam{FolderConfigs: folderConfigs}
		notifier.Send(folderConfigsParam)
	}

	err := storedconfig.UpdateFolderConfigs(c.Engine().GetConfiguration(), folderConfigs, logger)
	if err != nil {
		c.Logger().Err(err).Msg("couldn't update folder configs")
		notifier.SendShowMessage(sglsp.MTError, err.Error())
	}
}

func folderConfigsOrgSettingsEqual(folderConfig types.FolderConfig, storedConfig *types.FolderConfig) bool {
	return folderConfig.PreferredOrg == storedConfig.PreferredOrg &&
		folderConfig.OrgSetByUser == storedConfig.OrgSetByUser &&
		folderConfig.OrgMigratedFromGlobalConfig == storedConfig.OrgMigratedFromGlobalConfig
}

func updateFolderConfigOrg(c *config.Config, notifier noti.Notifier, storedConfig *types.FolderConfig, folderConfig *types.FolderConfig) {
	// As a safety net, ensure the folder config has the AutoDeterminedOrg, we never want to save without it.
	ensureFolderConfigHasAutoDeterminedOrg(c, notifier, storedConfig, folderConfig)

	// For configs that have been migrated, we use the org returned by LDX-Sync unless the user has set one.
	if folderConfig.OrgMigratedFromGlobalConfig {
		orgHasJustChanged := folderConfig.PreferredOrg != storedConfig.PreferredOrg
		if orgHasJustChanged {
			// Now we will use the user-provided org and opt them out of LDX-Sync.
			folderConfig.OrgSetByUser = true
		} else if !folderConfig.OrgSetByUser {
			// Ensure we blank the field, so we don't flip it back to an old value when the user disables auto org.
			folderConfig.PreferredOrg = ""
		}
	} else {
		migrateFolderConfigOrg(c, notifier, folderConfig)
	}
}

func migrateFolderConfigOrg(c *config.Config, notifier noti.Notifier, folderConfig *types.FolderConfig) {
	// If we are migrating a folderConfig provided by the user,
	// (e.g. values set in a repo's ".vscode/settings.json", but this is the first time LS is seeing the folder) ...
	if folderConfig.OrgSetByUser {
		// ... where they have said they don't want LDX-Sync, we simply save it as migrated skipping LDX-Sync lookup.
		folderConfig.OrgMigratedFromGlobalConfig = true
		return
	}

	// We need to blank the preferred org, as we don't want to use it, otherwise they would have set OrgSetByUser.
	folderConfig.PreferredOrg = ""

	// Get the best org from LDX-Sync again, because we need to know if the org returned was default or not.
	newOrgIsDefault := command.SetAutoBestOrgFromLdxSync(c, notifier, folderConfig, c.Organization())

	// Determine OrgSetByUser based on LDX-Sync result
	if folderConfig.AutoDeterminedOrg != c.Organization() || newOrgIsDefault {
		// LDX-Sync returned a different org or the default org
		folderConfig.OrgSetByUser = false
	} else {
		// Folder org matches global org after LDX-Sync, but it was not the default, meaning we should take it as using a custom user org.
		// No need to set the PreferredOrg, as we will inherit from the global.
		folderConfig.OrgSetByUser = true
	}

	folderConfig.OrgMigratedFromGlobalConfig = true
}

func ensureFolderConfigHasAutoDeterminedOrg(c *config.Config, notifier noti.Notifier, storedConfig *types.FolderConfig, folderConfig *types.FolderConfig) {
	if folderConfig.AutoDeterminedOrg == "" {
		// Folder configs should always save the AutoDeterminedOrg, regardless of if the user needs it.
		if storedConfig.AutoDeterminedOrg != "" {
			folderConfig.AutoDeterminedOrg = storedConfig.AutoDeterminedOrg
		} else {
			// Somehow we missed the workflows that set this, so just fetch it now.
			command.SetAutoBestOrgFromLdxSync(c, notifier, folderConfig, "")
		}
	}
}

func updateAuthenticationMethod(c *config.Config, settings types.Settings) {
	if types.EmptyAuthenticationMethod == settings.AuthenticationMethod {
		return
	}

	oldValue := c.AuthenticationMethod()
	c.SetAuthenticationMethod(settings.AuthenticationMethod)
	di.AuthenticationService().ConfigureProviders(c)

	if oldValue != settings.AuthenticationMethod {
		sendWorkspaceConfigChanged(c, "authenticationMethod", oldValue, settings.AuthenticationMethod, triggerSource)
	}
}

func updateRuntimeInfo(c *config.Config, settings types.Settings) {
	c.SetOsArch(settings.OsArch)
	c.SetOsPlatform(settings.OsPlatform)
	c.SetRuntimeVersion(settings.RuntimeVersion)
	c.SetRuntimeName(settings.RuntimeName)
}

func updateTrustedFolders(c *config.Config, settings types.Settings, triggerSource string) {
	trustedFoldersFeatureEnabled, err := strconv.ParseBool(settings.EnableTrustedFoldersFeature)
	if err == nil {
		oldValue := c.IsTrustedFolderFeatureEnabled()
		c.SetTrustedFolderFeatureEnabled(trustedFoldersFeatureEnabled)
		if oldValue != trustedFoldersFeatureEnabled {
			sendWorkspaceConfigChanged(c, "enableTrustedFoldersFeature", oldValue, trustedFoldersFeatureEnabled, triggerSource)
		}
	} else {
		c.SetTrustedFolderFeatureEnabled(true)
	}

	if settings.TrustedFolders != nil {
		oldFolders := c.TrustedFolders()
		var trustedFolders []types.FilePath
		for _, folder := range settings.TrustedFolders {
			trustedFolders = append(trustedFolders, types.FilePath(folder))
		}
		c.SetTrustedFolders(trustedFolders)

		// Send analytics for trusted folders change
		sendWorkspaceConfigChanged(c, "trustedFolders", oldFolders, trustedFolders, triggerSource)
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

func updateAutoScan(c *config.Config, settings types.Settings, triggerSource string) {
	// Auto scan true by default unless the AutoScan value in the settings is not missing & false
	autoScan := true
	if settings.ScanningMode == "manual" {
		autoScan = false
	}

	// TODO: Add getter method for AutomaticScanning to enable analytics
	c.SetAutomaticScanning(autoScan)
}

func updateSnykLearnCodeActions(c *config.Config, settings types.Settings, triggerSource string) {
	enable := true
	if settings.EnableSnykLearnCodeActions == "false" {
		enable = false
	}

	oldValue := c.IsSnykLearnCodeActionsEnabled()
	c.SetSnykLearnCodeActionsEnabled(enable)

	if oldValue != enable {
		sendWorkspaceConfigChanged(c, "enableSnykLearnCodeActions", oldValue, enable, triggerSource)
	}
}

func updateSnykOSSQuickFixCodeActions(c *config.Config, settings types.Settings, triggerSource string) {
	enable := true
	if settings.EnableSnykOSSQuickFixCodeActions == "false" {
		enable = false
	}

	oldValue := c.IsSnykOSSQuickFixCodeActionsEnabled()
	c.SetSnykOSSQuickFixCodeActionsEnabled(enable)

	if oldValue != enable {
		sendWorkspaceConfigChanged(c, "enableSnykOSSQuickFixCodeActions", oldValue, enable, triggerSource)
	}
}

func updateDeltaFindings(c *config.Config, settings types.Settings, triggerSource string) {
	enable := true
	if settings.EnableDeltaFindings == "" || settings.EnableDeltaFindings == "false" {
		enable = false
	}

	oldValue := c.IsDeltaFindingsEnabled()

	modified := c.SetDeltaFindingsEnabled(enable)
	if modified {
		sendWorkspaceConfigChanged(c, "enableDeltaFindings", oldValue, enable, triggerSource)
	}
}

func updateToken(token string) {
	// Token was sent from the client, no need to send notification
	di.AuthenticationService().UpdateCredentials(token, false, false)
}

func updateApiEndpoints(c *config.Config, settings types.Settings, initialization bool, triggerSource string) {
	snykApiUrl := strings.Trim(settings.Endpoint, " ")
	// TODO: Add getter method for Endpoint to enable analytics
	endpointsUpdated := c.UpdateApiEndpoints(snykApiUrl)

	if endpointsUpdated && !initialization {
		authService := di.AuthenticationService()
		authService.Logout(context.Background())
		authService.ConfigureProviders(c)
		c.Workspace().Clear()
	}

	// a custom set snyk code api (e.g. for testing) always overwrites automatic config
	if settings.SnykCodeApi != "" {
		oldCodeApi := c.SnykCodeApi()
		c.SetSnykCodeApi(settings.SnykCodeApi)
		if oldCodeApi != settings.SnykCodeApi {
			sendWorkspaceConfigChanged(c, "snykCodeApi", oldCodeApi, settings.SnykCodeApi, triggerSource)
		}
	}
}

func updateOrganization(c *config.Config, settings types.Settings, triggerSource string, sendAnalytics bool) {
	// Persist per-folder orgs using stored config.
	updatedAny := false
	for _, fc := range settings.FolderConfigs {
		org := strings.TrimSpace(fc.Organization)
		if org == "" {
			continue
		}
		// Persist to stored folder config
		current, err := storedconfig.GetOrCreateFolderConfig(c.Engine().GetConfiguration(), fc.FolderPath, c.Logger())
		if err == nil {
			if current.Organization != org {
				oldOrg := current.Organization
				current.Organization = org
				_ = storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), current, c.Logger())
				// Send analytics for organization change (only if user-triggered)
				if sendAnalytics {
					go sendConfigChangedAnalyticsEvent(c, "organization", oldOrg, org, fc.FolderPath, triggerSource)
				}
				updatedAny = true
			}
		}
	}

	// Legacy migration: if no folder configs provided orgs but legacy settings.Organization is set,
	// copy it into all provided folder configs and then clear global org.
	if !updatedAny {
		newOrg := strings.TrimSpace(settings.Organization)
		if newOrg != "" {
			migrated := 0
			for _, fc := range settings.FolderConfigs {
				current, err := storedconfig.GetOrCreateFolderConfig(c.Engine().GetConfiguration(), fc.FolderPath, c.Logger())
				if err == nil {
					if current.Organization != newOrg {
						oldOrg := current.Organization
						current.Organization = newOrg
						_ = storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), current, c.Logger())
						// Send analytics for organization change (only if user-triggered)
						if sendAnalytics {
							go sendConfigChangedAnalyticsEvent(c, "organization", oldOrg, newOrg, fc.FolderPath, triggerSource)
						}
						migrated++
					}
				}
			}
			if migrated > 0 {
				// clear legacy global org after successful migration
				c.SetOrganization("")
			}
		}
	}
}

func updateErrorReporting(c *config.Config, settings types.Settings, triggerSource string) {
	parseBool, err := strconv.ParseBool(settings.SendErrorReports)
	if err != nil {
		c.Logger().Debug().Msgf("couldn't read send error reports %s", settings.SendErrorReports)
	} else {
		oldValue := c.IsErrorReportingEnabled()
		c.SetErrorReportingEnabled(parseBool)

		if oldValue != parseBool {
			sendWorkspaceConfigChanged(c, "sendErrorReports", oldValue, parseBool, triggerSource)
		}
	}
}

func manageBinariesAutomatically(c *config.Config, settings types.Settings, triggerSource string) {
	parseBool, err := strconv.ParseBool(settings.ManageBinariesAutomatically)
	if err != nil {
		c.Logger().Debug().Msgf("couldn't read manage binaries automatically %s", settings.ManageBinariesAutomatically)
	} else {
		oldValue := c.ManageBinariesAutomatically()
		c.SetManageBinariesAutomatically(parseBool)

		if oldValue != parseBool {
			sendWorkspaceConfigChanged(c, "manageBinariesAutomatically", oldValue, parseBool, triggerSource)
		}
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

// TODO stop using os env, move parsing to CLI
func updatePathFromSettings(c *config.Config, settings types.Settings, initialize bool) {
	logger := c.Logger().With().Str("method", "updatePathFromSettings").Logger()

	// Although we will update the PATH now, we also need to store the value, so that on scans we can ensure it is prepended
	// in front of everything else that is added.
	c.SetUserSettingsPath(settings.Path)

	if initialize || !c.IsDefaultEnvReady() {
		// If we are initializing then we don't actually need to do anything else, as PATH is in a clean state with no prior
		// settings.Path entries, and the first scan will prepend the most recent setting.Path entry for us.
		return
	}

	var newPath string
	if len(settings.Path) > 0 {
		_ = os.Unsetenv("Path") // unset the path first to work around issues on Windows OS, where PATH can be Path
		logger.Debug().Msg("adding configured path to PATH")
		newPath = settings.Path + string(os.PathListSeparator) + c.GetCachedOriginalPath()
	} else {
		logger.Debug().Msg("restoring initial path")
		newPath = c.GetCachedOriginalPath()
	}

	err := os.Setenv("PATH", newPath)
	if err != nil {
		logger.Err(err).Msgf("couldn't add path %s", settings.Path)
	}
	logger.Debug().Msgf("new PATH is '%s'", os.Getenv("PATH"))
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

func updateProductEnablement(c *config.Config, settings types.Settings, triggerSource string, sendAnalytics bool) {
	// Snyk Code
	parseBool, err := strconv.ParseBool(settings.ActivateSnykCode)
	if err != nil {
		c.Logger().Debug().Msg("couldn't parse code setting")
	} else {
		oldValue := c.IsSnykCodeEnabled()
		c.SetSnykCodeEnabled(parseBool)
		c.EnableSnykCodeSecurity(parseBool)
		if oldValue != parseBool && sendAnalytics {
			sendWorkspaceConfigChanged(c, "activateSnykCode", oldValue, parseBool, triggerSource)
		}
	}

	// Snyk Open Source
	parseBool, err = strconv.ParseBool(settings.ActivateSnykOpenSource)
	if err != nil {
		c.Logger().Debug().Msg("couldn't parse open source setting")
	} else {
		oldValue := c.IsSnykOssEnabled()
		c.SetSnykOssEnabled(parseBool)
		if oldValue != parseBool && sendAnalytics {
			sendWorkspaceConfigChanged(c, "activateSnykOpenSource", oldValue, parseBool, triggerSource)
		}
	}

	// Snyk IaC
	parseBool, err = strconv.ParseBool(settings.ActivateSnykIac)
	if err != nil {
		c.Logger().Debug().Msg("couldn't parse iac setting")
	} else {
		oldValue := c.IsSnykIacEnabled()
		c.SetSnykIacEnabled(parseBool)
		if oldValue != parseBool && sendAnalytics {
			sendWorkspaceConfigChanged(c, "activateSnykIac", oldValue, parseBool, triggerSource)
		}
	}
}

func updateIssueViewOptions(c *config.Config, s *types.IssueViewOptions, triggerSource string) {
	c.Logger().Debug().Str("method", "updateIssueViewOptions").Interface("issueViewOptions", s).Msg("Updating issue view options:")
	modified := c.SetIssueViewOptions(s)

	if modified {
		sendWorkspaceConfigChanged(c, "", nil, nil, triggerSource)
	}
}

func updateSeverityFilter(c *config.Config, s *types.SeverityFilter, triggerSource string) {
	c.Logger().Debug().Str("method", "updateSeverityFilter").Interface("severityFilter", s).Msg("Updating severity filter:")
	modified := c.SetSeverityFilter(s)

	if modified {
		sendWorkspaceConfigChanged(c, "", nil, nil, triggerSource)
	}
}

func sendWorkspaceConfigChanged(c *config.Config, configName string, oldVal any, newVal any, triggerSource string) {
	ws := c.Workspace()
	if ws == nil {
		return
	}
	go ws.HandleConfigChange()

	if len(configName) == 0 {
		return
	}
	for _, folder := range ws.Folders() {
		go sendConfigChangedAnalyticsEvent(c, configName, oldVal, newVal, folder.Path(), triggerSource)
	}
}

func sendConfigChangedAnalyticsEvent(c *config.Config, field string, oldValue, newValue interface{}, path types.FilePath, triggerSource string) {
	event := analytics.NewAnalyticsEventParam("Config changed", nil, path)

	event.Extension = map[string]any{
		"config::" + field + "::oldValue":      oldValue,
		"config::" + field + "::newValue":      newValue,
		"config::" + field + "::triggerSource": triggerSource,
	}
	analytics.SendAnalytics(c.Engine(), c.DeviceID(), event, nil)
}
