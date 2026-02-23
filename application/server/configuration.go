/*
 * © 2022-2026 Snyk Limited All rights reserved.
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

// Package server implements the server functionality
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/handler"
	"github.com/google/go-cmp/cmp"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	sglsp "github.com/sourcegraph/go-lsp"

	mcpWorkflow "github.com/snyk/snyk-ls/internal/mcp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/infrastructure/analytics"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

// Constants for configName strings used in analytics
const (
	configActivateSnykCode                    = "activateSnykCode"
	configActivateSnykIac                     = "activateSnykIac"
	configActivateSnykSecrets                 = "activateSnykSecrets"
	configActivateSnykOpenSource              = "activateSnykOpenSource"
	configAdditionalParameters                = "additionalParameters"
	configAuthenticationMethod                = "authenticationMethod"
	configBaseBranch                          = "baseBranch"
	configCliBaseDownloadURL                  = "cliBaseDownloadURL"
	configEnableDeltaFindings                 = "enableDeltaFindings"
	configEnableSnykLearnCodeActions          = "enableSnykLearnCodeActions"
	configEnableSnykOSSQuickFixCodeActions    = "enableSnykOSSQuickFixCodeActions"
	configEnableTrustedFoldersFeature         = "enableTrustedFoldersFeature"
	configEndpoint                            = "endpoint"
	configFolderPath                          = "folderPath"
	configLocalBranches                       = "localBranches"
	configManageBinariesAutomatically         = "manageBinariesAutomatically"
	configOrgMigratedFromGlobalConfig         = "orgMigratedFromGlobalConfig"
	configOrgSetByUser                        = "orgSetByUser"
	configOrganization                        = "organization"
	configPreferredOrg                        = "preferredOrg"
	configReferenceFolderPath                 = "referenceFolderPath"
	configScanCommandConfig                   = "scanCommandConfig"
	configSendErrorReports                    = "sendErrorReports"
	configSnykCodeApi                         = "snykCodeApi"
	configAutoConfigureSnykMcpServer          = "autoConfigureSnykMcpServer"
	configSecureAtInceptionExecutionFrequency = "secureAtInceptionExecutionFrequency"
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
		UpdateSettings(c, params.Settings, analytics.TriggerSourceInitialize)
		return true, nil
	}

	// Subsequent calls - this is a user change
	UpdateSettings(c, params.Settings, analytics.TriggerSourceIDE)
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
	if len(fetchedSettings) == 0 {
		return false, nil
	}

	emptySettings := types.Settings{}
	c.Logger().Debug().Interface("settings", fetchedSettings[0]).Msg("Fetched settings from workspace/configuration")
	if !reflect.DeepEqual(fetchedSettings[0], emptySettings) {
		if !c.IsLSPInitialized() {
			// First time - this is initialization
			UpdateSettings(c, fetchedSettings[0], analytics.TriggerSourceInitialize)
			return true, nil
		}

		// Subsequent calls - this is a user change
		UpdateSettings(c, fetchedSettings[0], analytics.TriggerSourceIDE)
		return true, nil
	}

	// Empty settings - do nothing
	return false, nil
}

func InitializeSettings(c *config.Config, settings types.Settings) {
	writeSettings(c, settings, analytics.TriggerSourceInitialize)
	updateAutoAuthentication(c, settings)
	updateDeviceInformation(c, settings)
	// updateAutoScan is already called within writeSettings with batch propagation.
	// Call it again here to ensure auto scan state is set even if writeSettings
	// returned early (e.g., empty settings). Propagation is a no-op since the
	// discarded map is not used.
	updateAutoScan(c, settings, make(map[string]any))
	c.SetClientProtocolVersion(settings.RequiredProtocolVersion)
}

func UpdateSettings(c *config.Config, settings types.Settings, triggerSource analytics.TriggerSource) {
	ws := c.Workspace()

	// Capture "before" state per folder
	previousState := make(map[types.FilePath]map[product.FilterableIssueType]bool)
	if ws != nil {
		for _, folder := range ws.Folders() {
			previousState[folder.Path()] = folder.DisplayableIssueTypes()
		}
	}

	writeSettings(c, settings, triggerSource)

	// If a product was removed for a folder, clear all issues for that product in that folder
	if ws != nil {
		for _, folder := range ws.Folders() {
			newState := folder.DisplayableIssueTypes()
			for issueType, wasEnabled := range previousState[folder.Path()] {
				if wasEnabled && !newState[issueType] {
					folder.ClearDiagnosticsByIssueType(issueType)
				}
			}
		}
	}
}

func writeSettings(c *config.Config, settings types.Settings, triggerSource analytics.TriggerSource) {
	c.Engine().GetConfiguration().ClearCache()

	emptySettings := types.Settings{}
	if reflect.DeepEqual(settings, emptySettings) {
		return
	}

	// Update ConfigResolver with global settings for machine-scope resolution
	if resolver := di.ConfigResolver(); resolver != nil {
		resolver.SetGlobalSettings(&settings)
	}

	// Collect org-scoped setting changes for batch propagation to FolderConfigs.
	// This avoids redundant load/save cycles.
	pendingPropagations := make(map[string]any)

	updateSeverityFilter(c, settings.FilterSeverity, triggerSource, pendingPropagations)
	updateRiskScoreThreshold(c, settings, triggerSource, pendingPropagations)
	updateIssueViewOptions(c, settings.IssueViewOptions, triggerSource, pendingPropagations)
	updateProductEnablement(c, settings, triggerSource, pendingPropagations)
	updateCliConfig(c, settings)
	updateApiEndpoints(c, settings, triggerSource) // Must be called before token is set, as it may trigger a logout which clears the token.
	updateCliBaseDownloadURL(c, settings, triggerSource)
	updateToken(settings.Token) // Must be called before the Authentication method is set, as the latter checks the token.
	updateAuthenticationMethod(c, settings, triggerSource)
	updateEnvironment(c, settings)
	updatePathFromSettings(c, settings)
	updateErrorReporting(c, settings, triggerSource)
	updateOrganization(c, settings, triggerSource)
	manageBinariesAutomatically(c, settings, triggerSource)
	updateTrustedFolders(c, settings, triggerSource)
	updateRuntimeInfo(c, settings)
	updateAutoScan(c, settings, pendingPropagations)
	updateSnykLearnCodeActions(c, settings, triggerSource)
	updateSnykOSSQuickFixCodeActions(c, settings, triggerSource)
	updateSnykOpenBrowserCodeActions(c, settings)
	updateDeltaFindings(c, settings, triggerSource, pendingPropagations)
	updateFolderConfig(c, settings, c.Logger(), triggerSource)
	updateHoverVerbosity(c, settings)
	updateFormat(c, settings)
	updateMcpConfiguration(c, settings, triggerSource)
	updateProxyConfig(c, settings)
	updateCodeEndpoint(c, settings)
	updatePublishSecurityAtInceptionRules(c, settings)
	updateCliReleaseChannel(c, settings)

	// Clear stale folder overrides for org-scoped settings changed at global level,
	// so the new global value takes effect via ConfigResolver's precedence chain.
	batchClearOrgScopedOverridesOnGlobalChange(c, pendingPropagations)
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
	enable := settings.EnableSnykOpenBrowserActions == "true"

	// TODO: Add getter method for SnykOpenBrowserActionsEnabled to enable analytics
	c.SetSnykOpenBrowserActionsEnabled(enable)
}

func updateFolderConfig(c *config.Config, settings types.Settings, logger *zerolog.Logger, triggerSource analytics.TriggerSource) {
	notifier := di.Notifier()
	incomingMap := buildIncomingLspConfigMap(settings.FolderConfigs)
	allPaths := gatherAllFolderPathsFromLspConfigs(incomingMap, c.Workspace())

	logger.Debug().
		Int("incomingFolderConfigCount", len(settings.FolderConfigs)).
		Int("incomingMapCount", len(incomingMap)).
		Int("allPathsCount", len(allPaths)).
		Msg("updateFolderConfig - processing folder configs")

	var folderConfigs []types.FolderConfig
	var changedConfigs []*types.FolderConfig
	needsToSendUpdateToClient := false

	for path := range allPaths {
		folderConfig, oldConfig, configChanged := processSingleLspFolderConfig(c, path, incomingMap, notifier)

		if configChanged {
			needsToSendUpdateToClient = true
			changedConfigs = append(changedConfigs, &folderConfig)
		}

		handleFolderCacheClearing(c, path, oldConfig, folderConfig, logger, triggerSource)
		folderConfigs = append(folderConfigs, folderConfig)
	}

	// Batch-persist all changed folder configs in a single load/save cycle
	if len(changedConfigs) > 0 {
		if err := c.BatchUpdateFolderConfigs(changedConfigs); err != nil {
			logger.Err(err).Int("count", len(changedConfigs)).Msg("failed to batch update folder configs")
		}
	}

	sendFolderConfigUpdateIfNeeded(c, notifier, folderConfigs, needsToSendUpdateToClient, triggerSource)
}

func buildIncomingLspConfigMap(folderConfigs []types.LspFolderConfig) map[types.FilePath]types.LspFolderConfig {
	incomingMap := make(map[types.FilePath]types.LspFolderConfig)
	for _, fc := range folderConfigs {
		// Normalize the path to ensure consistent lookup
		normalizedPath := types.PathKey(fc.FolderPath)
		incomingMap[normalizedPath] = fc
	}
	return incomingMap
}

func gatherAllFolderPathsFromLspConfigs(incomingMap map[types.FilePath]types.LspFolderConfig, workspace types.Workspace) map[types.FilePath]bool {
	allPaths := make(map[types.FilePath]bool)

	// Add incoming paths
	for path := range incomingMap {
		allPaths[path] = true
	}

	// Add stored paths from all workspace folders
	if workspace != nil {
		for _, folder := range workspace.Folders() {
			allPaths[folder.Path()] = true
		}
	}

	return allPaths
}

// processSingleLspFolderConfig processes an incoming LspFolderConfig from the IDE using PATCH semantics:
// - For pointer fields: nil = don't change, non-nil = set value
// - For NullableField[T]: omitted = don't change, null = reset to default, value = set override
// It loads the existing FolderConfig (read-only), applies the LspFolderConfig updates, and returns
// the processed config without persisting. The caller is responsible for batch-persisting all changes.
// Returns: (processedConfig, oldConfig, configChanged)
func processSingleLspFolderConfig(c *config.Config, path types.FilePath, incomingMap map[types.FilePath]types.LspFolderConfig, notifier notification.Notifier) (types.FolderConfig, *types.FolderConfig, bool) {
	logger := c.Logger().With().Str("method", "processSingleLspFolderConfig").Str("path", string(path)).Logger()

	// Read-only load: no writes to storage
	immutable := c.ImmutableFolderConfig(path)
	var storedConfig *types.FolderConfig
	if fc, ok := immutable.(*types.FolderConfig); ok && fc != nil {
		storedConfig = fc
	}

	// Start with existing stored config or create new
	var folderConfig types.FolderConfig
	if storedConfig != nil {
		folderConfig = *storedConfig
	} else {
		folderConfig = types.FolderConfig{FolderPath: path}
	}

	// Validate that the changes are allowed, then apply the new config.
	normalizedPath := types.PathKey(path)
	if incoming, hasIncoming := incomingMap[normalizedPath]; hasIncoming {
		// Validate locked fields before applying
		hasLockedFieldRejections := validateLockedFields(c, &folderConfig, &incoming, &logger)
		if hasLockedFieldRejections {
			folderName := filepath.Base(string(folderConfig.FolderPath))
			notifier.SendShowMessage(sglsp.MTWarning,
				fmt.Sprintf("Failed to update %s: Some settings are locked by your organization's policy", folderName))
		}

		// Apply the PATCH update
		folderConfig.ApplyLspUpdate(&incoming)
	}

	updateFolderOrgIfNeeded(c, storedConfig, &folderConfig, notifier)
	di.FeatureFlagService().PopulateFolderConfig(&folderConfig)

	configChanged := storedConfig == nil || !cmp.Equal(folderConfig, *storedConfig)

	return folderConfig, storedConfig, configChanged
}

// validateLockedFields checks if any fields in the incoming LspFolderConfig are locked by LDX-Sync.
// Returns true if any fields were rejected due to being locked.
// If the incoming update changes PreferredOrg, locks are evaluated against the NEW org's policies
// to prevent bypassing stricter locks during an org switch.
func validateLockedFields(c *config.Config, folderConfig *types.FolderConfig, incoming *types.LspFolderConfig, logger *zerolog.Logger) bool {
	resolver := di.ConfigResolver()
	if resolver == nil {
		return false
	}

	// If the incoming update changes PreferredOrg, evaluate locks against the new org.
	// Without this, a simultaneous org switch + setting change would be validated against
	// the old org's policies, potentially bypassing the new org's stricter locks.
	configForValidation := folderConfig
	if incoming.PreferredOrg != nil && *incoming.PreferredOrg != folderConfig.PreferredOrg {
		updated := *folderConfig
		updated.PreferredOrg = *incoming.PreferredOrg
		updated.OrgSetByUser = true
		configForValidation = &updated
	}

	updatesRejected := false

	// Check each org-scope setting that might be locked (only if field is present in update)
	fieldsToCheck := map[string]bool{
		types.SettingEnabledSeverities:      incoming.EnabledSeverities.Present,
		types.SettingRiskScoreThreshold:     incoming.RiskScoreThreshold.Present,
		types.SettingScanAutomatic:          incoming.ScanAutomatic.Present,
		types.SettingScanNetNew:             incoming.ScanNetNew.Present,
		types.SettingSnykCodeEnabled:        incoming.SnykCodeEnabled.Present,
		types.SettingSnykOssEnabled:         incoming.SnykOssEnabled.Present,
		types.SettingSnykIacEnabled:         incoming.SnykIacEnabled.Present,
		types.SettingIssueViewOpenIssues:    incoming.IssueViewOpenIssues.Present,
		types.SettingIssueViewIgnoredIssues: incoming.IssueViewIgnoredIssues.Present,
		types.SettingCweIds:                 incoming.CweIds.Present,
		types.SettingCveIds:                 incoming.CveIds.Present,
		types.SettingRuleIds:                incoming.RuleIds.Present,
	}

	for settingName, hasUpdate := range fieldsToCheck {
		if !hasUpdate {
			continue
		}
		_, source := resolver.GetValue(settingName, configForValidation)
		if source == types.ConfigSourceLDXSyncLocked {
			logger.Info().
				Str("setting", settingName).
				Msg("Rejecting change to locked setting - enforced by organization policy")
			updatesRejected = true
			// Clear the field in incoming so ApplyLspUpdate won't apply it
			clearLockedField(incoming, settingName)
		}
	}

	return updatesRejected
}

// clearLockedField marks a locked field as omitted so ApplyLspUpdate won't apply it
func clearLockedField(incoming *types.LspFolderConfig, settingName string) {
	// Set Present=false to mark as omitted (don't change)
	switch settingName {
	case types.SettingEnabledSeverities:
		incoming.EnabledSeverities.Present = false
	case types.SettingRiskScoreThreshold:
		incoming.RiskScoreThreshold.Present = false
	case types.SettingScanAutomatic:
		incoming.ScanAutomatic.Present = false
	case types.SettingScanNetNew:
		incoming.ScanNetNew.Present = false
	case types.SettingSnykCodeEnabled:
		incoming.SnykCodeEnabled.Present = false
	case types.SettingSnykOssEnabled:
		incoming.SnykOssEnabled.Present = false
	case types.SettingSnykIacEnabled:
		incoming.SnykIacEnabled.Present = false
	case types.SettingIssueViewOpenIssues:
		incoming.IssueViewOpenIssues.Present = false
	case types.SettingIssueViewIgnoredIssues:
		incoming.IssueViewIgnoredIssues.Present = false
	case types.SettingCweIds:
		incoming.CweIds.Present = false
	case types.SettingCveIds:
		incoming.CveIds.Present = false
	case types.SettingRuleIds:
		incoming.RuleIds.Present = false
	}
}

func updateFolderOrgIfNeeded(c *config.Config, storedConfig *types.FolderConfig, folderConfig *types.FolderConfig, notifier notification.Notifier) {
	needsMigration := storedConfig != nil && !storedConfig.OrgMigratedFromGlobalConfig
	orgSettingsChanged := storedConfig != nil && !folderConfigsOrgSettingsEqual(*folderConfig, storedConfig)

	if needsMigration || orgSettingsChanged {
		updateFolderConfigOrg(c, storedConfig, folderConfig)

		// User changed org settings, refresh from LDX-Sync
		if orgSettingsChanged {
			folder := c.Workspace().GetFolderContaining(folderConfig.FolderPath)
			if folder != nil {
				di.LdxSyncService().RefreshConfigFromLdxSync(context.Background(), c, []types.Folder{folder}, notifier)
			}
		}
	}
}

func handleFolderCacheClearing(c *config.Config, path types.FilePath, oldConfig *types.FolderConfig, folderConfig types.FolderConfig, logger *zerolog.Logger, triggerSource analytics.TriggerSource) {
	if oldConfig == nil {
		return
	}

	baseBranchChanged := oldConfig.BaseBranch != folderConfig.BaseBranch
	referenceFolderChanged := oldConfig.ReferenceFolderPath != folderConfig.ReferenceFolderPath

	if baseBranchChanged || referenceFolderChanged {
		logger.Info().
			Str("folderPath", string(path)).
			Str("oldBaseBranch", oldConfig.BaseBranch).
			Str("newBaseBranch", folderConfig.BaseBranch).
			Str("oldReferenceFolderPath", string(oldConfig.ReferenceFolderPath)).
			Str("newReferenceFolderPath", string(folderConfig.ReferenceFolderPath)).
			Msg("base branch or reference folder changed, clearing persisted scan cache for folder")

		ws := c.Workspace()
		if ws != nil {
			ws.GetScanSnapshotClearerExister().ClearFolder(path)
		}
	}

	sendFolderConfigAnalytics(c, path, triggerSource, *oldConfig, folderConfig)
}

func sendFolderConfigUpdateIfNeeded(c *config.Config, notifier notification.Notifier, folderConfigs []types.FolderConfig, needsToSendUpdate bool, triggerSource analytics.TriggerSource) {
	// Don't send folder configs on initialize, since initialized will always send them.
	if needsToSendUpdate && triggerSource != analytics.TriggerSourceInitialize {
		resolver := di.ConfigResolver()
		lspConfigs := make([]types.LspFolderConfig, 0, len(folderConfigs))
		for _, fc := range folderConfigs {
			// Convert to LspFolderConfig with effective values computed by resolver
			lspConfig := fc.ToLspFolderConfig(resolver)
			if lspConfig != nil {
				lspConfigs = append(lspConfigs, *lspConfig)
			}
		}
		notifier.Send(types.LspFolderConfigsParam{FolderConfigs: lspConfigs})
	}
}

func sendFolderConfigAnalytics(c *config.Config, path types.FilePath, triggerSource analytics.TriggerSource, oldStoredConfig, newStoredConfig types.FolderConfig) {
	// FolderPath change
	if oldStoredConfig.FolderPath != newStoredConfig.FolderPath {
		go analytics.SendConfigChangedAnalyticsEvent(c, configFolderPath, oldStoredConfig.FolderPath, newStoredConfig.FolderPath, path, triggerSource)
	}

	// BaseBranch change
	if oldStoredConfig.BaseBranch != newStoredConfig.BaseBranch {
		go analytics.SendConfigChangedAnalyticsEvent(c, configBaseBranch, oldStoredConfig.BaseBranch, newStoredConfig.BaseBranch, path, triggerSource)
	}

	// LocalBranches change
	// Dont send analytics for newStoredConfig.LocalBranches

	// AdditionalParameters change
	if !util.SlicesEqualIgnoringOrder(oldStoredConfig.AdditionalParameters, newStoredConfig.AdditionalParameters) {
		oldParamsJSON, _ := json.Marshal(oldStoredConfig.AdditionalParameters)
		newParamsJSON, _ := json.Marshal(newStoredConfig.AdditionalParameters)
		go analytics.SendConfigChangedAnalyticsEvent(c, configAdditionalParameters, string(oldParamsJSON), string(newParamsJSON), path, triggerSource)
	}

	// ReferenceFolderPath change
	if oldStoredConfig.ReferenceFolderPath != newStoredConfig.ReferenceFolderPath {
		go analytics.SendConfigChangedAnalyticsEvent(c, configReferenceFolderPath, oldStoredConfig.ReferenceFolderPath, newStoredConfig.ReferenceFolderPath, path, triggerSource)
	}

	// ScanCommandConfig change
	if !reflect.DeepEqual(oldStoredConfig.ScanCommandConfig, newStoredConfig.ScanCommandConfig) {
		oldConfigJSON, _ := json.Marshal(oldStoredConfig.ScanCommandConfig)
		newConfigJSON, _ := json.Marshal(newStoredConfig.ScanCommandConfig)
		go analytics.SendConfigChangedAnalyticsEvent(c, configScanCommandConfig, string(oldConfigJSON), string(newConfigJSON), path, triggerSource)
	}

	// PreferredOrg change
	if oldStoredConfig.PreferredOrg != newStoredConfig.PreferredOrg && newStoredConfig.PreferredOrg != "" {
		go analytics.SendConfigChangedAnalyticsEvent(c, configPreferredOrg, oldStoredConfig.PreferredOrg, newStoredConfig.PreferredOrg, path, triggerSource)
	}

	// OrgMigratedFromGlobalConfig change
	if oldStoredConfig.OrgMigratedFromGlobalConfig != newStoredConfig.OrgMigratedFromGlobalConfig {
		go analytics.SendConfigChangedAnalyticsEvent(c, configOrgMigratedFromGlobalConfig, oldStoredConfig.OrgMigratedFromGlobalConfig, newStoredConfig.OrgMigratedFromGlobalConfig, path, triggerSource)
	}

	// OrgSetByUser change
	if oldStoredConfig.OrgSetByUser != newStoredConfig.OrgSetByUser {
		go analytics.SendConfigChangedAnalyticsEvent(c, configOrgSetByUser, oldStoredConfig.OrgSetByUser, newStoredConfig.OrgSetByUser, path, triggerSource)
	}
}

func folderConfigsOrgSettingsEqual(folderConfig types.FolderConfig, storedConfig *types.FolderConfig) bool {
	return folderConfig.PreferredOrg == storedConfig.PreferredOrg &&
		folderConfig.OrgSetByUser == storedConfig.OrgSetByUser &&
		folderConfig.OrgMigratedFromGlobalConfig == storedConfig.OrgMigratedFromGlobalConfig &&
		folderConfig.AutoDeterminedOrg == storedConfig.AutoDeterminedOrg
}

func updateFolderConfigOrg(c *config.Config, storedConfig *types.FolderConfig, folderConfig *types.FolderConfig) {
	// As a safety net, ensure the folder config has the AutoDeterminedOrg.
	if folderConfig.AutoDeterminedOrg == "" {
		// Folder configs should always save the AutoDeterminedOrg, regardless of if the user needs it.
		if storedConfig.AutoDeterminedOrg != "" {
			folderConfig.AutoDeterminedOrg = storedConfig.AutoDeterminedOrg
		} else {
			// Case when Folder Configs were provided as part of initialize request
			// or when user is not logged in during initialized notification
			// Only set if LDX-Sync has a result - fallback to global org happens in FolderOrganization
			cache := c.GetLdxSyncOrgConfigCache()
			if orgId := cache.GetOrgIdForFolder(folderConfig.FolderPath); orgId != "" {
				folderConfig.AutoDeterminedOrg = orgId
			}
		}
	}

	// If we have just received settings where folder config claims org is not migrated, but we know we have previously
	// migrated it, correct that here.
	if !folderConfig.OrgMigratedFromGlobalConfig && storedConfig.OrgMigratedFromGlobalConfig {
		folderConfig.OrgMigratedFromGlobalConfig = true
	}

	if !folderConfig.OrgMigratedFromGlobalConfig {
		command.MigrateFolderConfigOrgSettings(c, folderConfig)
		return
	}

	// For configs that have been migrated, we use the org returned by LDX-Sync unless the user has set one.
	orgSetByUserJustChanged := folderConfig.OrgSetByUser != storedConfig.OrgSetByUser
	orgHasJustChanged := folderConfig.PreferredOrg != storedConfig.PreferredOrg
	// If the user changes both OrgSetByUser and PreferredOrg, we will prioritize OrgSetByUser changes.
	if orgSetByUserJustChanged {
		if !folderConfig.OrgSetByUser {
			// Ensure we blank the field, so we don't flip it back to an old value when the user disables auto org.
			folderConfig.PreferredOrg = ""
		}
	} else if orgHasJustChanged {
		// Now we will use the user-provided org and opt them out of LDX-Sync.
		folderConfig.OrgSetByUser = true
	} else if !folderConfig.OrgSetByUser {
		// Ensure we blank the field, so we don't flip it back to an old value when the user disables auto org.
		folderConfig.PreferredOrg = ""
	}
}

func updateAuthenticationMethod(c *config.Config, settings types.Settings, triggerSource analytics.TriggerSource) {
	if types.EmptyAuthenticationMethod == settings.AuthenticationMethod {
		return
	}

	oldValue := c.AuthenticationMethod()
	c.SetAuthenticationMethod(settings.AuthenticationMethod)
	di.AuthenticationService().ConfigureProviders(c)

	if oldValue != settings.AuthenticationMethod && c.IsLSPInitialized() {
		analytics.SendConfigChangedAnalytics(c, configAuthenticationMethod, oldValue, settings.AuthenticationMethod, triggerSource)
	}
}

func updateRuntimeInfo(c *config.Config, settings types.Settings) {
	c.SetOsArch(settings.OsArch)
	c.SetOsPlatform(settings.OsPlatform)
	c.SetRuntimeVersion(settings.RuntimeVersion)
	c.SetRuntimeName(settings.RuntimeName)
}

func updateTrustedFolders(c *config.Config, settings types.Settings, triggerSource analytics.TriggerSource) {
	// Not all changes to the trusted folders are updated in the config here. They are actually updated in other parts of the application.
	// So we are not actually sending analytics for all changes to the trusted folders here.

	trustedFoldersFeatureEnabled, err := strconv.ParseBool(settings.EnableTrustedFoldersFeature)
	if err == nil {
		oldValue := c.IsTrustedFolderFeatureEnabled()
		c.SetTrustedFolderFeatureEnabled(trustedFoldersFeatureEnabled)
		if oldValue != trustedFoldersFeatureEnabled && c.IsLSPInitialized() {
			analytics.SendConfigChangedAnalytics(c, configEnableTrustedFoldersFeature, oldValue, trustedFoldersFeatureEnabled, triggerSource)
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
		if !util.SlicesEqualIgnoringOrder(oldFolders, trustedFolders) && c.IsLSPInitialized() {
			// Send analytics for individual folder changes to all workspace folders
			oldFoldersJSON, _ := json.Marshal(oldFolders)
			newFoldersJSON, _ := json.Marshal(trustedFolders)
			go analytics.SendConfigChangedAnalyticsEvent(c, "trustedFolder", string(oldFoldersJSON), string(newFoldersJSON), types.FilePath(""), triggerSource)
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

func updateAutoScan(c *config.Config, settings types.Settings, pendingPropagations map[string]any) {
	// Auto scan true by default unless the AutoScan value in the settings is not missing & false
	autoScan := settings.ScanningMode != "manual"

	// TODO: Add getter method for AutomaticScanning to enable analytics
	c.SetAutomaticScanning(autoScan)

	pendingPropagations[types.SettingScanAutomatic] = autoScan
}

func updateSnykLearnCodeActions(c *config.Config, settings types.Settings, triggerSource analytics.TriggerSource) {
	enable := settings.EnableSnykLearnCodeActions != "false"

	oldValue := c.IsSnykLearnCodeActionsEnabled()
	c.SetSnykLearnCodeActionsEnabled(enable)

	if oldValue != enable && c.IsLSPInitialized() {
		analytics.SendConfigChangedAnalytics(c, configEnableSnykLearnCodeActions, oldValue, enable, triggerSource)
	}
}

func updateSnykOSSQuickFixCodeActions(c *config.Config, settings types.Settings, triggerSource analytics.TriggerSource) {
	enable := settings.EnableSnykOSSQuickFixCodeActions != "false"

	oldValue := c.IsSnykOSSQuickFixCodeActionsEnabled()
	c.SetSnykOSSQuickFixCodeActionsEnabled(enable)

	if oldValue != enable && c.IsLSPInitialized() {
		analytics.SendConfigChangedAnalytics(c, configEnableSnykOSSQuickFixCodeActions, oldValue, enable, triggerSource)
	}
}

func updateDeltaFindings(c *config.Config, settings types.Settings, triggerSource analytics.TriggerSource, pendingPropagations map[string]any) {
	enable := settings.EnableDeltaFindings != "" && settings.EnableDeltaFindings != "false"

	oldValue := c.IsDeltaFindingsEnabled()

	modified := c.SetDeltaFindingsEnabled(enable)
	if modified {
		pendingPropagations[types.SettingScanNetNew] = enable

		if c.IsLSPInitialized() {
			sendDiagnosticsForNewSettings(c)
			analytics.SendConfigChangedAnalytics(c, configEnableDeltaFindings, oldValue, enable, triggerSource)
		}
	}
}

func updateToken(token string) {
	// Token was sent from the client, no need to send notification
	di.AuthenticationService().UpdateCredentials(token, false, false)
}

func updateApiEndpoints(c *config.Config, settings types.Settings, triggerSource analytics.TriggerSource) {
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
			analytics.SendConfigChangedAnalytics(c, configEndpoint, oldEndpoint, snykApiUrl, triggerSource)
		}
	}
}

func updateCliBaseDownloadURL(c *config.Config, settings types.Settings, triggerSource analytics.TriggerSource) {
	newCliBaseDownloadURL := strings.TrimSpace(settings.CliBaseDownloadURL)

	oldCliBaseDownloadURL := c.CliBaseDownloadURL()
	c.SetCliBaseDownloadURL(newCliBaseDownloadURL)

	if oldCliBaseDownloadURL != newCliBaseDownloadURL && c.IsLSPInitialized() {
		analytics.SendConfigChangedAnalytics(c, configCliBaseDownloadURL, oldCliBaseDownloadURL, newCliBaseDownloadURL, triggerSource)
	}
}

func updateOrganization(c *config.Config, settings types.Settings, triggerSource analytics.TriggerSource) {
	// Only update global org if explicitly provided (not nil)
	if settings.Organization == nil {
		return
	}
	newOrg := strings.TrimSpace(*settings.Organization)
	oldOrgId := c.Organization()
	c.SetOrganization(newOrg)
	newOrgId := c.Organization() // Read the org from config so we are guaranteed to have a UUID instead of a slug.
	if oldOrgId != newOrgId && c.IsLSPInitialized() {
		analytics.SendConfigChangedAnalytics(c, configOrganization, oldOrgId, newOrgId, triggerSource)
	}
}

func updateErrorReporting(c *config.Config, settings types.Settings, triggerSource analytics.TriggerSource) {
	parseBool, err := strconv.ParseBool(settings.SendErrorReports)
	if err != nil {
		c.Logger().Debug().Msgf("couldn't read send error reports %s", settings.SendErrorReports)
	} else {
		oldValue := c.IsErrorReportingEnabled()
		c.SetErrorReportingEnabled(parseBool)

		if oldValue != parseBool && c.IsLSPInitialized() {
			analytics.SendConfigChangedAnalytics(c, configSendErrorReports, oldValue, parseBool, triggerSource)
		}
	}
}

func manageBinariesAutomatically(c *config.Config, settings types.Settings, triggerSource analytics.TriggerSource) {
	parseBool, err := strconv.ParseBool(settings.ManageBinariesAutomatically)
	if err != nil {
		c.Logger().Debug().Msgf("couldn't read manage binaries automatically %s", settings.ManageBinariesAutomatically)
	} else {
		oldValue := c.ManageBinariesAutomatically()
		c.SetManageBinariesAutomatically(parseBool)

		if oldValue != parseBool && c.IsLSPInitialized() {
			analytics.SendConfigChangedAnalytics(c, configManageBinariesAutomatically, oldValue, parseBool, triggerSource)
		}
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

func updateProductEnablement(c *config.Config, settings types.Settings, triggerSource analytics.TriggerSource, pendingPropagations map[string]any) {
	// Snyk Code is enabled if activateSnykCode or activateSnykCodeSecurity are enabled. activateSnykCodeSecurity is a
	// legacy field but might be reported by the IDEs if set by MDM.
	codeEnabled, codeErr := strconv.ParseBool(settings.ActivateSnykCode)
	codeSecurityEnabled, codeSecErr := strconv.ParseBool(settings.ActivateSnykCodeSecurity)
	if codeErr == nil || codeSecErr == nil {
		resolved := codeEnabled || codeSecurityEnabled
		oldValue := c.IsSnykCodeEnabled()
		c.SetSnykCodeEnabled(resolved)
		if oldValue != resolved {
			pendingPropagations[types.SettingSnykCodeEnabled] = resolved
			if c.IsLSPInitialized() {
				analytics.SendConfigChangedAnalytics(c, configActivateSnykCode, oldValue, resolved, triggerSource)
			}
		}
	}

	// Snyk Open Source
	parseBool, err := strconv.ParseBool(settings.ActivateSnykOpenSource)
	if err != nil {
		c.Logger().Debug().Msg("couldn't parse open source setting")
	} else {
		oldValue := c.IsSnykOssEnabled()
		c.SetSnykOssEnabled(parseBool)
		if oldValue != parseBool {
			pendingPropagations[types.SettingSnykOssEnabled] = parseBool
			if c.IsLSPInitialized() {
				analytics.SendConfigChangedAnalytics(c, configActivateSnykOpenSource, oldValue, parseBool, triggerSource)
			}
		}
	}

	// Snyk IaC
	parseBool, err = strconv.ParseBool(settings.ActivateSnykIac)
	if err != nil {
		c.Logger().Debug().Msg("couldn't parse iac setting")
	} else {
		oldValue := c.IsSnykIacEnabled()
		c.SetSnykIacEnabled(parseBool)
		if oldValue != parseBool {
			pendingPropagations[types.SettingSnykIacEnabled] = parseBool
			if c.IsLSPInitialized() {
				analytics.SendConfigChangedAnalytics(c, configActivateSnykIac, oldValue, parseBool, triggerSource)
			}
		}

		// Snyk Secrets
		parseBool, err = strconv.ParseBool(settings.ActivateSnykSecrets)
		if err != nil {
			c.Logger().Debug().Msg("couldn't parse secrets setting")
		} else {
			oldValue := c.IsSnykSecretsEnabled()
			c.SetSnykSecretsEnabled(parseBool)
			if oldValue != parseBool && c.IsLSPInitialized() {
				analytics.SendConfigChangedAnalytics(c, configActivateSnykSecrets, oldValue, parseBool, triggerSource)
			}
		}
	}
}

func updateIssueViewOptions(c *config.Config, s *types.IssueViewOptions, triggerSource analytics.TriggerSource, pendingPropagations map[string]any) {
	c.Logger().Debug().Str("method", "updateIssueViewOptions").Interface("issueViewOptions", s).Msg("Updating issue view options")
	oldValue := c.IssueViewOptions()
	modified := c.SetIssueViewOptions(s)

	if !modified {
		return
	}

	if s != nil {
		pendingPropagations[types.SettingIssueViewOpenIssues] = s.OpenIssues
		pendingPropagations[types.SettingIssueViewIgnoredIssues] = s.IgnoredIssues
	}

	// Send UI update
	sendDiagnosticsForNewSettings(c)

	// Send analytics for each individual field that changed
	if c.IsLSPInitialized() {
		analytics.SendAnalyticsForFields(c, "issueViewOptions", &oldValue, s, triggerSource, map[string]func(*types.IssueViewOptions) any{
			"OpenIssues":    func(s *types.IssueViewOptions) any { return s.OpenIssues },
			"IgnoredIssues": func(s *types.IssueViewOptions) any { return s.IgnoredIssues },
		})
	}
}

func updateRiskScoreThreshold(c *config.Config, settings types.Settings, triggerSource analytics.TriggerSource, pendingPropagations map[string]any) {
	c.Logger().Debug().Str("method", "updateRiskScoreThreshold").Interface("riskScoreThreshold", settings.RiskScoreThreshold).Msg("Updating risk score threshold")
	oldValue := c.RiskScoreThreshold()
	modified := c.SetRiskScoreThreshold(settings.RiskScoreThreshold)

	if !modified {
		return
	}

	pendingPropagations[types.SettingRiskScoreThreshold] = settings.RiskScoreThreshold

	// Send UI update
	sendDiagnosticsForNewSettings(c)

	// Send analytics
	if c.IsLSPInitialized() && settings.RiskScoreThreshold != nil {
		analytics.SendConfigChangedAnalytics(c, "riskScoreThreshold", oldValue, *settings.RiskScoreThreshold, triggerSource)
	}
}

func updateSeverityFilter(c *config.Config, s *types.SeverityFilter, triggerSource analytics.TriggerSource, pendingPropagations map[string]any) {
	c.Logger().Debug().Str("method", "updateSeverityFilter").Interface("severityFilter", s).Msg("Updating severity filter")
	oldValue := c.FilterSeverity()
	modified := c.SetSeverityFilter(s)

	if !modified {
		return
	}

	pendingPropagations[types.SettingEnabledSeverities] = s

	// Send UI update
	sendDiagnosticsForNewSettings(c)

	// Send analytics for each individual field that changed
	if c.IsLSPInitialized() {
		analytics.SendAnalyticsForFields(c, "filterSeverity", &oldValue, s, triggerSource, map[string]func(*types.SeverityFilter) any{
			"Critical": func(s *types.SeverityFilter) any { return s.Critical },
			"High":     func(s *types.SeverityFilter) any { return s.High },
			"Medium":   func(s *types.SeverityFilter) any { return s.Medium },
			"Low":      func(s *types.SeverityFilter) any { return s.Low },
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

func updateMcpConfiguration(c *config.Config, settings types.Settings, triggerSource analytics.TriggerSource) {
	logger := c.Logger().With().Str("method", "updateMcpConfiguration").Logger()
	n := di.Notifier()
	// Update autoConfigureSnykMcpServer
	if settings.AutoConfigureSnykMcpServer != "" {
		parseBool, err := strconv.ParseBool(settings.AutoConfigureSnykMcpServer)
		if err != nil {
			logger.Debug().Msgf("couldn't parse autoConfigureSnykMcpServer %s", settings.AutoConfigureSnykMcpServer)
		} else {
			oldValue := c.IsAutoConfigureMcpEnabled()
			c.SetAutoConfigureMcpEnabled(parseBool)

			if oldValue != parseBool {
				if c.IsLSPInitialized() {
					go analytics.SendConfigChangedAnalytics(c, configAutoConfigureSnykMcpServer, oldValue, parseBool, triggerSource)
				}
				mcpWorkflow.CallMcpConfigWorkflow(c, n, true, false)
			}
		}
	}

	// Update secureAtInceptionExecutionFrequency
	if settings.SecureAtInceptionExecutionFrequency != "" {
		oldValue := c.GetSecureAtInceptionExecutionFrequency()
		c.SetSecureAtInceptionExecutionFrequency(settings.SecureAtInceptionExecutionFrequency)

		if oldValue != settings.SecureAtInceptionExecutionFrequency {
			if c.IsLSPInitialized() {
				go analytics.SendConfigChangedAnalytics(c, configSecureAtInceptionExecutionFrequency, oldValue, settings.SecureAtInceptionExecutionFrequency, triggerSource)
			}
			mcpWorkflow.CallMcpConfigWorkflow(c, n, false, true)
		}
	}
}

func updateProxyConfig(c *config.Config, settings types.Settings) {
	if settings.ProxyHttp != "" {
		c.SetProxyHttp(settings.ProxyHttp)
	}
	if settings.ProxyHttps != "" {
		c.SetProxyHttps(settings.ProxyHttps)
	}
	if settings.ProxyNoProxy != "" {
		c.SetProxyNoProxy(settings.ProxyNoProxy)
	}
}

func updateCodeEndpoint(c *config.Config, settings types.Settings) {
	if settings.SnykCodeApi != "" {
		c.SetCodeEndpoint(strings.TrimSpace(settings.SnykCodeApi))
	}
}

func updatePublishSecurityAtInceptionRules(c *config.Config, settings types.Settings) {
	if settings.PublishSecurityAtInceptionRules != "" {
		parseBool, err := strconv.ParseBool(settings.PublishSecurityAtInceptionRules)
		if err != nil {
			c.Logger().Debug().Msgf("couldn't parse publishSecurityAtInceptionRules %s", settings.PublishSecurityAtInceptionRules)
		} else {
			c.SetPublishSecurityAtInceptionRulesEnabled(parseBool)
		}
	}
}

func updateCliReleaseChannel(c *config.Config, settings types.Settings) {
	if settings.CliReleaseChannel != "" {
		c.SetCliReleaseChannel(strings.TrimSpace(settings.CliReleaseChannel))
	}
}

// batchClearOrgScopedOverridesOnGlobalChange clears UserOverrides for org-scoped settings
// that were changed at the global level. This ensures the global value takes effect via
// ConfigResolver's precedence chain (which checks global settings before LDX-Sync defaults).
// Without clearing, stale folder-level overrides would shadow the new global value.
// Non-org-scoped settings in the pending map are silently ignored.
// Settings that are locked by LDX-Sync for a folder's org are skipped (locked values always win).
func batchClearOrgScopedOverridesOnGlobalChange(c *config.Config, pending map[string]any) {
	if len(pending) == 0 {
		return
	}

	// Filter to only org-scoped settings
	var orgScopedNames []string
	for settingName := range pending {
		if types.IsOrgScopedSetting(settingName) {
			orgScopedNames = append(orgScopedNames, settingName)
		}
	}
	if len(orgScopedNames) == 0 {
		return
	}

	logger := c.Logger().With().Str("method", "batchClearOrgScopedOverridesOnGlobalChange").Logger()
	gafConfig := c.Engine().GetConfiguration()

	sc, err := storedconfig.GetStoredConfig(gafConfig, &logger, true)
	if err != nil {
		logger.Err(err).Msg("Failed to get stored config for clearing overrides on global change")
		return
	}

	cache := c.GetLdxSyncOrgConfigCache()
	modified := false

	for folderPath, fc := range sc.FolderConfigs {
		if fc == nil || fc.UserOverrides == nil || len(fc.UserOverrides) == 0 {
			continue
		}
		if clearFolderOverridesForSettings(fc, folderPath, orgScopedNames, cache, &logger) {
			modified = true
		}
	}

	if modified {
		if err := storedconfig.Save(gafConfig, sc); err != nil {
			logger.Err(err).Msg("Failed to save stored config after clearing overrides")
		} else {
			logger.Debug().Int("settingCount", len(orgScopedNames)).Msg("Saved stored config after clearing overrides on global change")
		}
	}
}

func clearFolderOverridesForSettings(fc *types.FolderConfig, folderPath types.FilePath, settingNames []string, cache *types.LDXSyncConfigCache, logger *zerolog.Logger) bool {
	var orgConfig *types.LDXSyncOrgConfig
	effectiveOrg := cache.GetOrgIdForFolder(folderPath)
	if effectiveOrg != "" {
		orgConfig = cache.GetOrgConfig(effectiveOrg)
	}

	cleared := false
	for _, settingName := range settingNames {
		if orgConfig != nil {
			field := orgConfig.GetField(settingName)
			if field != nil && field.IsLocked {
				logger.Debug().
					Str("folder", string(folderPath)).
					Str("org", effectiveOrg).
					Str("setting", settingName).
					Msg("Skipping override clear - field is locked by org policy")
				continue
			}
		}

		if _, hasOverride := fc.UserOverrides[settingName]; hasOverride {
			delete(fc.UserOverrides, settingName)
			cleared = true
			logger.Debug().
				Str("folder", string(folderPath)).
				Str("setting", settingName).
				Msg("Cleared folder override so global value takes effect")
		}
	}
	return cleared
}
