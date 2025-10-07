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
	"cmp"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
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
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/types"
)

// Constants for configName strings used in analytics
const (
	configActivateSnykCode                 = "activateSnykCode"
	configActivateSnykIac                  = "activateSnykIac"
	configActivateSnykOpenSource           = "activateSnykOpenSource"
	configAdditionalParameters             = "additionalParameters"
	configAuthenticationMethod             = "authenticationMethod"
	configBaseBranch                       = "baseBranch"
	configEnableDeltaFindings              = "enableDeltaFindings"
	configEnableSnykLearnCodeActions       = "enableSnykLearnCodeActions"
	configEnableSnykOSSQuickFixCodeActions = "enableSnykOSSQuickFixCodeActions"
	configEnableTrustedFoldersFeature      = "enableTrustedFoldersFeature"
	configEndpoint                         = "endpoint"
	configFolderPath                       = "folderPath"
	configLocalBranches                    = "localBranches"
	configManageBinariesAutomatically      = "manageBinariesAutomatically"
	configOrgMigratedFromGlobalConfig      = "orgMigratedFromGlobalConfig"
	configOrgSetByUser                     = "orgSetByUser"
	configOrganization                     = "organization"
	configPreferredOrg                     = "preferredOrg"
	configReferenceFolderPath              = "referenceFolderPath"
	configSendErrorReports                 = "sendErrorReports"
	configSnykCodeApi                      = "snykCodeApi"
)

func workspaceDidChangeConfiguration(c *config.Config, srv *jrpc2.Server) jrpc2.Handler {
	return handler.New(func(ctx context.Context, params types.DidChangeConfigurationParams) (bool, error) {
		// we don't log the received config, as it could contain credentials that are not yet filtered.
		// it should be enough to log once we leave the handler
		defer c.Logger().Info().Str("method", "WorkspaceDidChangeConfiguration").Interface("params", params).Msg("DONE")

		emptySettings := types.Settings{}

		if !reflect.DeepEqual(params.Settings, emptySettings) {
			// Push model - client sent settings directly
			return handlePushModel(c, params)
		}

		// Pull model - client sent empty settings
		return handlePullModel(c, srv, ctx)
	})
}

func handlePushModel(c *config.Config, params types.DidChangeConfigurationParams) (bool, error) {
	if !c.IsLSPInitialized() {
		// First time - this is initialization
		UpdateSettings(c, params.Settings, "initialize")
		return true, nil
	}

	// Subsequent calls - this is a user change
	UpdateSettings(c, params.Settings, "ide")
	return true, nil
}

func handlePullModel(c *config.Config, srv *jrpc2.Server, ctx context.Context) (bool, error) {
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

	emptySettings := types.Settings{}
	if !reflect.DeepEqual(fetchedSettings[0], emptySettings) {
		if !c.IsLSPInitialized() {
			// First time - this is initialization
			UpdateSettings(c, fetchedSettings[0], "initialize")
			return true, nil
		}

		// Subsequent calls - this is a user change
		UpdateSettings(c, fetchedSettings[0], "ide")
		return true, nil
	}

	// Empty settings - do nothing
	return false, nil
}

func InitializeSettings(c *config.Config, settings types.Settings) {
	writeSettings(c, settings, "initialize")
	updateAutoAuthentication(c, settings)
	updateDeviceInformation(c, settings)
	updateAutoScan(c, settings)
	c.SetClientProtocolVersion(settings.RequiredProtocolVersion)
}

func UpdateSettings(c *config.Config, settings types.Settings, triggerSource string) {
	previouslyEnabledProducts := c.DisplayableIssueTypes()
	writeSettings(c, settings, triggerSource)

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

func writeSettings(c *config.Config, settings types.Settings, triggerSource string) {
	c.Engine().GetConfiguration().ClearCache()

	emptySettings := types.Settings{}
	if reflect.DeepEqual(settings, emptySettings) {
		return
	}

	updateSeverityFilter(c, settings.FilterSeverity, triggerSource)
	updateIssueViewOptions(c, settings.IssueViewOptions, triggerSource)
	updateProductEnablement(c, settings, triggerSource)
	updateCliConfig(c, settings)
	updateApiEndpoints(c, settings, triggerSource) // Must be called before token is set, as it may trigger a logout which clears the token.
	updateToken(settings.Token)                    // Must be called before the Authentication method is set, as the latter checks the token.
	updateAuthenticationMethod(c, settings, triggerSource)
	updateEnvironment(c, settings)
	updatePathFromSettings(c, settings)
	updateErrorReporting(c, settings, triggerSource)
	updateOrganization(c, settings, triggerSource)
	manageBinariesAutomatically(c, settings, triggerSource)
	updateTrustedFolders(c, settings, triggerSource)
	updateSnykCodeSecurity(c, settings)
	updateRuntimeInfo(c, settings)
	updateAutoScan(c, settings)
	updateSnykLearnCodeActions(c, settings, triggerSource)
	updateSnykOSSQuickFixCodeActions(c, settings, triggerSource)
	updateSnykOpenBrowserCodeActions(c, settings)
	updateDeltaFindings(c, settings, triggerSource)
	updateFolderConfig(c, settings, c.Logger(), triggerSource)
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

	// TODO: Add getter method for SnykOpenBrowserActionsEnabled to enable analytics
	c.SetSnykOpenBrowserActionsEnabled(enable)
}

func updateFolderConfig(c *config.Config, settings types.Settings, logger *zerolog.Logger, triggerSource string) {
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

		// Store the old values before updating
		oldFolderPath := storedConfig.FolderPath
		oldBaseBranch := storedConfig.BaseBranch
		oldLocalBranches := storedConfig.LocalBranches
		oldAdditionalParameters := storedConfig.AdditionalParameters
		oldReferenceFolderPath := storedConfig.ReferenceFolderPath
		oldScanCommandConfig := storedConfig.ScanCommandConfig
		oldOrg := storedConfig.PreferredOrg
		oldOrgMigratedFromGlobalConfig := storedConfig.OrgMigratedFromGlobalConfig
		oldOrgSetByUser := storedConfig.OrgSetByUser

		// Folder config might be new or changed, so (re)resolve the org before saving it.
		// We should also check that the folder's org is still valid if the globally set org has changed.
		// Also, if the config hasn't been migrated yet, we need to perform the initial migration.
		needsMigration := !storedConfig.OrgMigratedFromGlobalConfig
		orgSettingsChanged := !folderConfigsOrgSettingsEqual(folderConfig, storedConfig)

		if needsMigration || orgSettingsChanged {
			updateFolderConfigOrg(c, notifier, storedConfig, &folderConfig)
			folderConfigsMayHaveChanged = true
		}

		sendFolderConfigAnalytics(c, path, triggerSource, oldFolderPath, oldBaseBranch, oldLocalBranches, oldAdditionalParameters, oldReferenceFolderPath, oldScanCommandConfig, oldOrg, oldOrgMigratedFromGlobalConfig, oldOrgSetByUser, &folderConfig)

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

func sendFolderConfigAnalytics(c *config.Config, path types.FilePath, triggerSource string, oldFolderPath types.FilePath, oldBaseBranch string, oldLocalBranches, oldAdditionalParameters []string, oldReferenceFolderPath types.FilePath, oldScanCommandConfig map[product.Product]types.ScanCommandConfig, oldOrg string, oldOrgMigratedFromGlobalConfig, oldOrgSetByUser bool, storedConfig *types.FolderConfig) {
	// FolderPath change
	if oldFolderPath != storedConfig.FolderPath {
		go sendConfigChangedAnalyticsEvent(c, configFolderPath, oldFolderPath, storedConfig.FolderPath, path, triggerSource)
	}

	// BaseBranch change
	if oldBaseBranch != storedConfig.BaseBranch {
		go sendConfigChangedAnalyticsEvent(c, configBaseBranch, oldBaseBranch, storedConfig.BaseBranch, path, triggerSource)
	}

	// LocalBranches change
	if !slicesEqualIgnoringOrder(oldLocalBranches, storedConfig.LocalBranches) {
		go sendArrayConfigChangedAnalytics(c, configLocalBranches, oldLocalBranches, storedConfig.LocalBranches, path, triggerSource)
	}

	// AdditionalParameters change
	if !slicesEqualIgnoringOrder(oldAdditionalParameters, storedConfig.AdditionalParameters) {
		go sendArrayConfigChangedAnalytics(c, configAdditionalParameters, oldAdditionalParameters, storedConfig.AdditionalParameters, path, triggerSource)
	}

	// ReferenceFolderPath change
	if oldReferenceFolderPath != storedConfig.ReferenceFolderPath {
		go sendConfigChangedAnalyticsEvent(c, configReferenceFolderPath, oldReferenceFolderPath, storedConfig.ReferenceFolderPath, path, triggerSource)
	}

	// ScanCommandConfig change
	if !reflect.DeepEqual(oldScanCommandConfig, storedConfig.ScanCommandConfig) {
		go sendMapConfigChangedAnalytics(c, "scanCommandConfig", oldScanCommandConfig, storedConfig.ScanCommandConfig, path, triggerSource)
	}

	// PreferredOrg change
	if oldOrg != storedConfig.PreferredOrg && storedConfig.PreferredOrg != "" {
		go sendConfigChangedAnalyticsEvent(c, configPreferredOrg, oldOrg, storedConfig.PreferredOrg, path, triggerSource)
	}

	// OrgMigratedFromGlobalConfig change
	if oldOrgMigratedFromGlobalConfig != storedConfig.OrgMigratedFromGlobalConfig {
		go sendConfigChangedAnalyticsEvent(c, configOrgMigratedFromGlobalConfig, oldOrgMigratedFromGlobalConfig, storedConfig.OrgMigratedFromGlobalConfig, path, triggerSource)
	}

	// OrgSetByUser change
	if oldOrgSetByUser != storedConfig.OrgSetByUser {
		go sendConfigChangedAnalyticsEvent(c, configOrgSetByUser, oldOrgSetByUser, storedConfig.OrgSetByUser, path, triggerSource)
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

func updateAuthenticationMethod(c *config.Config, settings types.Settings, triggerSource string) {
	if types.EmptyAuthenticationMethod == settings.AuthenticationMethod {
		return
	}

	oldValue := c.AuthenticationMethod()
	c.SetAuthenticationMethod(settings.AuthenticationMethod)
	di.AuthenticationService().ConfigureProviders(c)

	if oldValue != settings.AuthenticationMethod && c.IsLSPInitialized() {
		sendConfigChangedAnalytics(c, configAuthenticationMethod, oldValue, settings.AuthenticationMethod, triggerSource)
	}
}

func updateRuntimeInfo(c *config.Config, settings types.Settings) {
	c.SetOsArch(settings.OsArch)
	c.SetOsPlatform(settings.OsPlatform)
	c.SetRuntimeVersion(settings.RuntimeVersion)
	c.SetRuntimeName(settings.RuntimeName)
}

func updateTrustedFolders(c *config.Config, settings types.Settings, triggerSource string) {
	//Not all changes to the trusted folders are updated in the config here. They are actually updated in other parts of the application.
	//So we are not actually sending analytics for all changes to the trusted folders here.

	trustedFoldersFeatureEnabled, err := strconv.ParseBool(settings.EnableTrustedFoldersFeature)
	if err == nil {
		oldValue := c.IsTrustedFolderFeatureEnabled()
		c.SetTrustedFolderFeatureEnabled(trustedFoldersFeatureEnabled)
		if oldValue != trustedFoldersFeatureEnabled && c.IsLSPInitialized() {
			sendConfigChangedAnalytics(c, configEnableTrustedFoldersFeature, oldValue, trustedFoldersFeatureEnabled, triggerSource)
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

		// Send analytics for trusted folders changes if they actually changed
		if !slicesEqualIgnoringOrder(oldFolders, trustedFolders) && c.IsLSPInitialized() {
			// Send analytics for individual folder changes
			sendTrustedFoldersAnalytics(c, oldFolders, trustedFolders, triggerSource)
		}
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

	if oldValue != enable && c.IsLSPInitialized() {
		sendConfigChangedAnalytics(c, configEnableSnykLearnCodeActions, oldValue, enable, triggerSource)
	}
}

func updateSnykOSSQuickFixCodeActions(c *config.Config, settings types.Settings, triggerSource string) {
	enable := true
	if settings.EnableSnykOSSQuickFixCodeActions == "false" {
		enable = false
	}

	oldValue := c.IsSnykOSSQuickFixCodeActionsEnabled()
	c.SetSnykOSSQuickFixCodeActionsEnabled(enable)

	if oldValue != enable && c.IsLSPInitialized() {
		sendConfigChangedAnalytics(c, configEnableSnykOSSQuickFixCodeActions, oldValue, enable, triggerSource)
	}
}

func updateDeltaFindings(c *config.Config, settings types.Settings, triggerSource string) {
	enable := true
	if settings.EnableDeltaFindings == "" || settings.EnableDeltaFindings == "false" {
		enable = false
	}

	oldValue := c.IsDeltaFindingsEnabled()

	modified := c.SetDeltaFindingsEnabled(enable)
	if modified && c.IsLSPInitialized() {
		sendDiagnosticsForNewSettings(c)
		sendConfigChangedAnalytics(c, configEnableDeltaFindings, oldValue, enable, triggerSource)
	}
}

func updateToken(token string) {
	// Token was sent from the client, no need to send notification
	di.AuthenticationService().UpdateCredentials(token, false, false)
}

func updateApiEndpoints(c *config.Config, settings types.Settings, triggerSource string) {
	snykApiUrl := strings.Trim(settings.Endpoint, " ")
	oldEndpoint := c.Endpoint()
	endpointsUpdated := c.UpdateApiEndpoints(snykApiUrl)

	if endpointsUpdated && c.IsLSPInitialized() {
		authService := di.AuthenticationService()
		authService.Logout(context.Background())
		authService.ConfigureProviders(c)
		c.Workspace().Clear()

		// Send analytics for endpoint change if it actually changed
		if oldEndpoint != snykApiUrl && c.IsLSPInitialized() {
			sendConfigChangedAnalytics(c, configEndpoint, oldEndpoint, snykApiUrl, triggerSource)
		}
	}

	// a custom set snyk code api (e.g. for testing) always overwrites automatic config
	if settings.SnykCodeApi != "" {
		oldCodeApi := c.SnykCodeApi()
		c.SetSnykCodeApi(settings.SnykCodeApi)
		if oldCodeApi != settings.SnykCodeApi && c.IsLSPInitialized() {
			sendConfigChangedAnalytics(c, configSnykCodeApi, oldCodeApi, settings.SnykCodeApi, triggerSource)
		}
	}
}

func updateOrganization(c *config.Config, settings types.Settings, triggerSource string) {
	newOrg := strings.TrimSpace(settings.Organization)
	if newOrg != "" {
		oldOrgId := c.Organization()
		c.SetOrganization(newOrg)
		newOrgId := c.Organization() // Read the org from config so we are guaranteed to have a UUID instead of a slug.
		if oldOrgId != newOrgId && c.IsLSPInitialized() {
			sendConfigChangedAnalytics(c, configOrganization, oldOrgId, newOrgId, triggerSource)
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

		if oldValue != parseBool && c.IsLSPInitialized() {
			sendConfigChangedAnalytics(c, configSendErrorReports, oldValue, parseBool, triggerSource)
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

		if oldValue != parseBool && c.IsLSPInitialized() {
			sendConfigChangedAnalytics(c, configManageBinariesAutomatically, oldValue, parseBool, triggerSource)
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
func updatePathFromSettings(c *config.Config, settings types.Settings) {
	logger := c.Logger().With().Str("method", "updatePathFromSettings").Logger()

	// Although we will update the PATH now, we also need to store the value, so that on scans we can ensure it is prepended
	// in front of everything else that is added.
	c.SetUserSettingsPath(settings.Path)

	if c.IsLSPInitialized() || !c.IsDefaultEnvReady() {
		// If the default environment is not ready yet, we can't safely update the PATH
		// The first scan will prepend the most recent setting.Path entry for us.
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

func updateProductEnablement(c *config.Config, settings types.Settings, triggerSource string) {
	// Snyk Code
	parseBool, err := strconv.ParseBool(settings.ActivateSnykCode)
	if err != nil {
		c.Logger().Debug().Msg("couldn't parse code setting")
	} else {
		oldValue := c.IsSnykCodeEnabled()
		c.SetSnykCodeEnabled(parseBool)
		c.EnableSnykCodeSecurity(parseBool)
		if oldValue != parseBool && c.IsLSPInitialized() {
			sendConfigChangedAnalytics(c, configActivateSnykCode, oldValue, parseBool, triggerSource)
		}
	}

	// Snyk Open Source
	parseBool, err = strconv.ParseBool(settings.ActivateSnykOpenSource)
	if err != nil {
		c.Logger().Debug().Msg("couldn't parse open source setting")
	} else {
		oldValue := c.IsSnykOssEnabled()
		c.SetSnykOssEnabled(parseBool)
		if oldValue != parseBool && c.IsLSPInitialized() {
			sendConfigChangedAnalytics(c, configActivateSnykOpenSource, oldValue, parseBool, triggerSource)
		}
	}

	// Snyk IaC
	parseBool, err = strconv.ParseBool(settings.ActivateSnykIac)
	if err != nil {
		c.Logger().Debug().Msg("couldn't parse iac setting")
	} else {
		oldValue := c.IsSnykIacEnabled()
		c.SetSnykIacEnabled(parseBool)
		if oldValue != parseBool && c.IsLSPInitialized() {
			sendConfigChangedAnalytics(c, configActivateSnykIac, oldValue, parseBool, triggerSource)
		}
	}
}

func updateIssueViewOptions(c *config.Config, s *types.IssueViewOptions, triggerSource string) {
	c.Logger().Debug().Str("method", "updateIssueViewOptions").Interface("issueViewOptions", s).Msg("Updating issue view options:")
	oldValue := c.IssueViewOptions()
	modified := c.SetIssueViewOptions(s)

	if !modified {
		return
	}

	// Send UI update
	sendDiagnosticsForNewSettings(c)

	// Send analytics for each individual field that changed
	if c.IsLSPInitialized() {
		sendAnalyticsForFields(c, "issueViewOptions", &oldValue, s, triggerSource, map[string]func(*types.IssueViewOptions) bool{
			"OpenIssues":    func(s *types.IssueViewOptions) bool { return s.OpenIssues },
			"IgnoredIssues": func(s *types.IssueViewOptions) bool { return s.IgnoredIssues },
		})
	}
}

func updateSeverityFilter(c *config.Config, s *types.SeverityFilter, triggerSource string) {
	c.Logger().Debug().Str("method", "updateSeverityFilter").Interface("severityFilter", s).Msg("Updating severity filter:")
	oldValue := c.FilterSeverity()
	modified := c.SetSeverityFilter(s)

	if !modified {
		return
	}

	// Send UI update
	sendDiagnosticsForNewSettings(c)

	// Send analytics for each individual field that changed
	if c.IsLSPInitialized() {
		sendAnalyticsForFields(c, "filterSeverity", &oldValue, s, triggerSource, map[string]func(*types.SeverityFilter) bool{
			"Critical": func(s *types.SeverityFilter) bool { return s.Critical },
			"High":     func(s *types.SeverityFilter) bool { return s.High },
			"Medium":   func(s *types.SeverityFilter) bool { return s.Medium },
			"Low":      func(s *types.SeverityFilter) bool { return s.Low },
		})
	}
}

// sendDiagnosticsForNewSettings handles UI updates only (no analytics)
func sendDiagnosticsForNewSettings(c *config.Config) {
	ws := c.Workspace()
	if ws == nil {
		return
	}
	go ws.HandleConfigChange()
}

// sendConfigChangedAnalytics sends analytics for primitive values only
func sendConfigChangedAnalytics(c *config.Config, configName string, oldVal any, newVal any, triggerSource string) {
	ws := c.Workspace()
	if ws == nil {
		return
	}

	for _, folder := range ws.Folders() {
		go sendConfigChangedAnalyticsEvent(c, configName, oldVal, newVal, folder.Path(), triggerSource)
	}
}

// sendAnalyticsForFields is a generic helper function that sends analytics for struct fields
func sendAnalyticsForFields[T any](c *config.Config, prefix string, oldValue, newValue *T, triggerSource string, fieldMappings map[string]func(*T) bool) {
	for fieldName, getter := range fieldMappings {
		oldVal := getter(oldValue)
		newVal := getter(newValue)
		if oldVal != newVal {
			sendConfigChangedAnalytics(c, prefix+fieldName, oldVal, newVal, triggerSource)
		}
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

// sendCollectionChangeAnalytics is a generic helper function that sends analytics for collection changes
func sendCollectionChangeAnalytics[T comparable](c *config.Config, field string, oldValue, newValue []T, triggerSource string, addedSuffix, removedSuffix, countSuffix string) {
	// Create maps for easier lookup
	oldMap := make(map[T]bool)
	for _, item := range oldValue {
		oldMap[item] = true
	}

	newMap := make(map[T]bool)
	for _, item := range newValue {
		newMap[item] = true
	}

	// Find added items
	for _, item := range newValue {
		if !oldMap[item] {
			sendConfigChangedAnalytics(c, field+addedSuffix, "", item, triggerSource)
		}
	}

	// Find removed items
	for _, item := range oldValue {
		if !newMap[item] {
			sendConfigChangedAnalytics(c, field+removedSuffix, item, "", triggerSource)
		}
	}

	// Send count change analytics
	oldCount := len(oldValue)
	newCount := len(newValue)
	if oldCount != newCount {
		sendConfigChangedAnalytics(c, field+countSuffix, oldCount, newCount, triggerSource)
	}
}

// sendMapChangeAnalytics is a generic helper function that sends analytics for map changes
func sendMapChangeAnalytics[K comparable, V any](c *config.Config, field string, oldValue, newValue map[K]V, triggerSource string, addedSuffix, modifiedSuffix, removedSuffix, countSuffix string) {
	// Create maps for easier lookup
	oldMap := make(map[K]V)
	for k, v := range oldValue {
		oldMap[k] = v
	}

	newMap := make(map[K]V)
	for k, v := range newValue {
		newMap[k] = v
	}

	// Find added/modified keys
	for k, newV := range newValue {
		if oldV, exists := oldMap[k]; !exists {
			// Key was added
			sendConfigChangedAnalytics(c, field+addedSuffix, "", k, triggerSource)
		} else if !reflect.DeepEqual(oldV, newV) {
			// Key was modified
			sendConfigChangedAnalytics(c, field+modifiedSuffix, oldV, newV, triggerSource)
		}
	}

	// Find removed keys
	for k := range oldValue {
		if _, exists := newMap[k]; !exists {
			// Key was removed
			sendConfigChangedAnalytics(c, field+removedSuffix, k, "", triggerSource)
		}
	}

	// Send count change analytics
	oldCount := len(oldValue)
	newCount := len(newValue)
	if oldCount != newCount {
		sendConfigChangedAnalytics(c, field+countSuffix, oldCount, newCount, triggerSource)
	}
}

// sendArrayConfigChangedAnalytics sends analytics for array/slice fields
func sendArrayConfigChangedAnalytics[T comparable](c *config.Config, field string, oldValue, newValue []T, path types.FilePath, triggerSource string) {
	sendCollectionChangeAnalytics(c, field, oldValue, newValue, triggerSource, "Added", "Removed", "Count")
}

// sendMapConfigChangedAnalytics sends analytics for map fields
func sendMapConfigChangedAnalytics[K comparable, V any](c *config.Config, field string, oldValue, newValue map[K]V, path types.FilePath, triggerSource string) {
	sendMapChangeAnalytics(c, field, oldValue, newValue, triggerSource, "KeyAdded", "KeyModified", "KeyRemoved", "Count")
}

// sendTrustedFoldersAnalytics sends analytics for individual trusted folder changes
func sendTrustedFoldersAnalytics(c *config.Config, oldFolders, newFolders []types.FilePath, triggerSource string) {
	// Normalize paths before comparison to avoid false removal reports due to path normalization differences
	normalizedOldFolders := normalizeTrustedFolders(oldFolders)
	normalizedNewFolders := normalizeTrustedFolders(newFolders)

	sendCollectionChangeAnalytics(c, "trustedFolder", normalizedOldFolders, normalizedNewFolders, triggerSource, "Added", "Removed", "Count")
}

// normalizeTrustedFolders normalizes a slice of trusted folder paths for consistent comparison
func normalizeTrustedFolders(folders []types.FilePath) []types.FilePath {
	normalized := make([]types.FilePath, len(folders))
	for i, folder := range folders {
		normalized[i] = types.FilePath(filepath.Clean(string(folder)))
	}
	return normalized
}

// slicesEqualIgnoringOrder compares two slices for equality ignoring element order
func slicesEqualIgnoringOrder[T cmp.Ordered](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}

	// Create sorted copies to avoid modifying originals
	sortedA := make([]T, len(a))
	copy(sortedA, a)
	slices.Sort(sortedA)

	sortedB := make([]T, len(b))
	copy(sortedB, b)
	slices.Sort(sortedB)

	return slices.Equal(sortedA, sortedB)
}
