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
		defer c.Logger().Info().Str("method", "WorkspaceDidChangeConfiguration").Msg("DONE")

		if len(params.Settings) > 0 || len(params.FolderConfigs) > 0 {
			return handlePushModel(c, params)
		}

		return handlePullModel(c, srv, ctx)
	})
}

func handlePushModel(c *config.Config, params types.DidChangeConfigurationParams) (bool, error) {
	triggerSource := analytics.TriggerSourceIDE
	if !c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingIsLspInitialized)) {
		triggerSource = analytics.TriggerSourceInitialize
	}
	UpdateSettings(c, params.Settings, params.FolderConfigs, triggerSource)
	return true, nil
}

func handlePullModel(c *config.Config, srv *jrpc2.Server, ctx context.Context) (bool, error) {
	key := configuration.UserGlobalKey(types.SettingClientCapabilities)
	capabilities, ok := c.Engine().GetConfiguration().Get(key).(types.ClientCapabilities)
	if !ok {
		capabilities = types.ClientCapabilities{}
	}
	if !capabilities.Workspace.Configuration {
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

	var fetchedSettings []types.DidChangeConfigurationParams
	err = res.UnmarshalResult(&fetchedSettings)
	if err != nil {
		return false, err
	}
	if len(fetchedSettings) == 0 {
		return false, nil
	}

	fetched := fetchedSettings[0]
	if len(fetched.Settings) == 0 && len(fetched.FolderConfigs) == 0 {
		return false, nil
	}

	triggerSource := analytics.TriggerSourceIDE
	if !c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingIsLspInitialized)) {
		triggerSource = analytics.TriggerSourceInitialize
	}
	UpdateSettings(c, fetched.Settings, fetched.FolderConfigs, triggerSource)
	return true, nil
}

// processInitMetadata handles init-only metadata fields from InitializationOptions.
func processInitMetadata(c *config.Config, opts types.InitializationOptions) {
	conf := c.Engine().GetConfiguration()
	conf.Set(configuration.UserGlobalKey(types.SettingClientProtocolVersion), opts.RequiredProtocolVersion)

	if opts.DeviceId != "" {
		c.Engine().GetConfiguration().Set(configuration.UserGlobalKey(types.SettingDeviceId), strings.TrimSpace(opts.DeviceId))
	}
	conf.Set(configuration.UserGlobalKey(types.SettingOsArch), opts.OsArch)
	conf.Set(configuration.UserGlobalKey(types.SettingOsPlatform), opts.OsPlatform)
	conf.Set(configuration.UserGlobalKey(types.SettingRuntimeVersion), opts.RuntimeVersion)
	conf.Set(configuration.UserGlobalKey(types.SettingRuntimeName), opts.RuntimeName)

	if opts.HoverVerbosity != nil {
		conf.Set(configuration.UserGlobalKey(types.SettingHoverVerbosity), *opts.HoverVerbosity)
	}
	if opts.OutputFormat != nil {
		conf.Set(configuration.UserGlobalKey(types.SettingFormat), *opts.OutputFormat)
	}

	autoAuth := true
	if v, ok := settingBool(opts.Settings, types.SettingAutomaticAuthentication); ok {
		autoAuth = v
	}
	conf.Set(configuration.UserGlobalKey(types.SettingAutomaticAuthentication), autoAuth)

	applyPathToEnv(c, opts.Path)
	applyTrustedFolders(c, opts.TrustedFolders, analytics.TriggerSourceInitialize)

	// Auto scan true by default unless explicitly disabled
	autoScan := true
	if v, ok := settingStr(opts.Settings, types.SettingScanAutomatic); ok && v == "manual" {
		autoScan = false
	} else if b, bOk := settingBool(opts.Settings, types.SettingScanAutomatic); bOk {
		autoScan = b
	}
	conf.Set(configuration.UserGlobalKey(types.SettingScanAutomatic), autoScan)
}

// InitializeSettings processes settings from the LSP initialize request.
func InitializeSettings(c *config.Config, opts types.InitializationOptions) {
	processInitMetadata(c, opts)
	processConfigSettings(c, opts.Settings, analytics.TriggerSourceInitialize)
	processFolderConfigs(c, opts.FolderConfigs, analytics.TriggerSourceInitialize)
}

// UpdateSettings processes settings from workspace/didChangeConfiguration.
func UpdateSettings(c *config.Config, settings map[string]*types.ConfigSetting, folderConfigs []types.LspFolderConfig, triggerSource analytics.TriggerSource) {
	ws := c.Workspace()
	oldToken := config.GetToken(c.Engine().GetConfiguration())

	previousState := make(map[types.FilePath]map[product.FilterableIssueType]bool)
	if ws != nil {
		for _, folder := range ws.Folders() {
			previousState[folder.Path()] = folder.DisplayableIssueTypes()
		}
	}

	processConfigSettings(c, settings, triggerSource)
	processFolderConfigs(c, folderConfigs, triggerSource)

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

	refreshLdxSyncOnTokenChange(c, ws, oldToken)
}

func refreshLdxSyncOnTokenChange(c *config.Config, ws types.Workspace, oldToken string) {
	newToken := config.GetToken(c.Engine().GetConfiguration())
	if newToken == oldToken || newToken == "" || ws == nil {
		return
	}
	folders := ws.Folders()
	if len(folders) == 0 {
		return
	}
	c.Logger().Info().Msg("token changed via settings, refreshing LDX-Sync configuration")
	di.LdxSyncService().RefreshConfigFromLdxSync(context.Background(), c, folders, di.Notifier())
}

// processConfigSettings writes incoming settings to configuration and applies side effects.
// This replaces the old writeSettings + update* functions.
func processConfigSettings(c *config.Config, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource) {
	c.Engine().GetConfiguration().ClearCache()

	if len(settings) == 0 {
		return
	}

	propagations := make(map[string]any)

	applyApiEndpoints(c, settings, triggerSource)
	applyToken(c, settings)
	applyAuthenticationMethod(c, settings, triggerSource)
	applyAutomaticAuthentication(c, settings)
	applyProductEnablement(c, settings, triggerSource, propagations)
	applySeverityFilter(c, settings, triggerSource, propagations)
	applyRiskScoreThreshold(c, settings, triggerSource, propagations)
	applyIssueViewOptions(c, settings, triggerSource, propagations)
	applyDeltaFindings(c, settings, triggerSource, propagations)
	applyAutoScan(c, settings, propagations)
	applyOrganization(c, settings, triggerSource)
	applyCliConfig(c, settings)
	applyEnvironment(c, settings)
	applyCliBaseDownloadURL(c, settings, triggerSource)
	applyErrorReporting(c, settings, triggerSource)
	applyManageBinariesAutomatically(c, settings, triggerSource)
	applyTrustedFoldersFromSettings(c, settings, triggerSource)
	applySnykLearnCodeActions(c, settings, triggerSource)
	applySnykOssQuickFixCodeActions(c, settings, triggerSource)
	applySnykOpenBrowserActions(c, settings)
	applyMcpConfiguration(c, settings, triggerSource)
	applyProxyConfig(c, settings)
	applyCodeEndpoint(c, settings)
	applyPublishSecurityAtInceptionRules(c, settings)
	applyCliReleaseChannel(c, settings)

	batchClearOrgScopedOverridesOnGlobalChange(c, propagations)
}

// processFolderConfigs handles the folder configuration portion of incoming settings.
func processFolderConfigs(c *config.Config, folderConfigs []types.LspFolderConfig, triggerSource analytics.TriggerSource) {
	logger := c.Logger()
	notifier := di.Notifier()
	incomingMap := buildIncomingLspConfigMap(folderConfigs)
	allPaths := gatherAllFolderPathsFromLspConfigs(incomingMap, c.Workspace())

	logger.Debug().
		Int("incomingFolderConfigCount", len(folderConfigs)).
		Int("incomingMapCount", len(incomingMap)).
		Int("allPathsCount", len(allPaths)).
		Msg("processFolderConfigs - processing folder configs")

	var processedConfigs []types.FolderConfig
	var changedConfigs []*types.FolderConfig
	needsToSendUpdateToClient := false

	for path := range allPaths {
		folderConfig, oldSnapshot, newSnapshot, configChanged := processSingleLspFolderConfig(c, path, incomingMap, notifier)

		if configChanged {
			needsToSendUpdateToClient = true
			changedConfigs = append(changedConfigs, &folderConfig)
		}

		handleFolderCacheClearing(c, path, oldSnapshot, newSnapshot, logger, triggerSource)
		processedConfigs = append(processedConfigs, folderConfig)
	}

	if len(changedConfigs) > 0 {
		if err := storedconfig.BatchUpdateFolderConfigs(c.Engine().GetConfiguration(), changedConfigs, c.Logger()); err != nil {
			logger.Err(err).Int("count", len(changedConfigs)).Msg("failed to batch update folder configs")
		}
	}

	sendFolderConfigUpdateIfNeeded(c, notifier, processedConfigs, needsToSendUpdateToClient, triggerSource)
}

// --- Value extraction helpers ---

func settingStr(settings map[string]*types.ConfigSetting, name string) (string, bool) {
	s, ok := settings[name]
	if !ok || s == nil || !s.Changed {
		return "", false
	}
	str, ok := s.Value.(string)
	return str, ok
}

func settingBool(settings map[string]*types.ConfigSetting, name string) (bool, bool) {
	s, ok := settings[name]
	if !ok || s == nil || !s.Changed {
		return false, false
	}
	if b, ok := s.Value.(bool); ok {
		return b, true
	}
	if str, ok := s.Value.(string); ok {
		parsed, err := strconv.ParseBool(str)
		return parsed, err == nil
	}
	return false, false
}

func settingInt(settings map[string]*types.ConfigSetting, name string) (int, bool) {
	s, ok := settings[name]
	if !ok || s == nil || !s.Changed {
		return 0, false
	}
	if i, ok := s.Value.(int); ok {
		return i, true
	}
	if f, ok := s.Value.(float64); ok {
		return int(f), true
	}
	return 0, false
}

func settingIntPtr(settings map[string]*types.ConfigSetting, name string) *int {
	if v, ok := settingInt(settings, name); ok {
		return &v
	}
	return nil
}

func settingPresent(settings map[string]*types.ConfigSetting, name string) bool {
	s, ok := settings[name]
	return ok && s != nil && s.Changed
}

// --- Side-effect handlers ---

func applyApiEndpoints(c *config.Config, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource) {
	v, ok := settingStr(settings, types.SettingApiEndpoint)
	if !ok {
		return
	}
	snykApiUrl := strings.TrimSpace(v)
	conf := c.Engine().GetConfiguration()
	oldEndpoint := conf.GetString(configuration.UserGlobalKey(types.SettingApiEndpoint))
	endpointsUpdated := config.UpdateApiEndpointsOnConfig(conf, snykApiUrl)

	if endpointsUpdated && conf.GetBool(configuration.UserGlobalKey(types.SettingIsLspInitialized)) {
		authService := di.AuthenticationService()
		authService.Logout(context.Background())
		authService.ConfigureProviders(c)
		c.Workspace().Clear()
		if oldEndpoint != snykApiUrl {
			analytics.SendConfigChangedAnalytics(c, configEndpoint, oldEndpoint, snykApiUrl, triggerSource)
		}
	}
}

func applyToken(c *config.Config, settings map[string]*types.ConfigSetting) {
	if v, ok := settingStr(settings, types.SettingToken); ok && v != "" {
		di.AuthenticationService().UpdateCredentials(v, false, false)
	}
}

func applyAuthenticationMethod(c *config.Config, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource) {
	v, ok := settingStr(settings, types.SettingAuthenticationMethod)
	if !ok || types.AuthenticationMethod(v) == types.EmptyAuthenticationMethod {
		return
	}
	conf := c.Engine().GetConfiguration()
	oldValue := config.GetAuthenticationMethodFromConfig(conf)
	conf.Set(configuration.UserGlobalKey(types.SettingAuthenticationMethod), v)
	di.AuthenticationService().ConfigureProviders(c)
	if oldValue != types.AuthenticationMethod(v) && c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingIsLspInitialized)) {
		analytics.SendConfigChangedAnalytics(c, configAuthenticationMethod, oldValue, types.AuthenticationMethod(v), triggerSource)
	}
}

func applyAutomaticAuthentication(c *config.Config, settings map[string]*types.ConfigSetting) {
	if v, ok := settingBool(settings, types.SettingAutomaticAuthentication); ok {
		c.Engine().GetConfiguration().Set(configuration.UserGlobalKey(types.SettingAutomaticAuthentication), v)
	}
}

func applyProductEnablement(c *config.Config, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, propagations map[string]any) {
	conf := c.Engine().GetConfiguration()
	lspInit := conf.GetBool(configuration.UserGlobalKey(types.SettingIsLspInitialized))
	if v, ok := settingBool(settings, types.SettingSnykCodeEnabled); ok {
		key := configuration.UserGlobalKey(types.SettingSnykCodeEnabled)
		oldValue := conf.GetBool(key)
		conf.Set(key, v)
		if oldValue != v {
			propagations[types.SettingSnykCodeEnabled] = v
			if lspInit {
				analytics.SendConfigChangedAnalytics(c, configActivateSnykCode, oldValue, v, triggerSource)
			}
		}
	}

	if v, ok := settingBool(settings, types.SettingSnykOssEnabled); ok {
		key := configuration.UserGlobalKey(types.SettingSnykOssEnabled)
		oldValue := conf.GetBool(key)
		conf.Set(key, v)
		if oldValue != v {
			propagations[types.SettingSnykOssEnabled] = v
			if lspInit {
				analytics.SendConfigChangedAnalytics(c, configActivateSnykOpenSource, oldValue, v, triggerSource)
			}
		}
	}

	if v, ok := settingBool(settings, types.SettingSnykIacEnabled); ok {
		key := configuration.UserGlobalKey(types.SettingSnykIacEnabled)
		oldValue := conf.GetBool(key)
		conf.Set(key, v)
		if oldValue != v {
			propagations[types.SettingSnykIacEnabled] = v
			if lspInit {
				analytics.SendConfigChangedAnalytics(c, configActivateSnykIac, oldValue, v, triggerSource)
			}
		}
	}

	if v, ok := settingBool(settings, types.SettingSnykSecretsEnabled); ok {
		key := configuration.UserGlobalKey(types.SettingSnykSecretsEnabled)
		oldValue := conf.GetBool(key)
		conf.Set(key, v)
		if oldValue != v {
			propagations[types.SettingSnykSecretsEnabled] = v
			if lspInit {
				analytics.SendConfigChangedAnalytics(c, configActivateSnykSecrets, oldValue, v, triggerSource)
			}
		}
	}
}

func applySeverityFilter(c *config.Config, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, propagations map[string]any) {
	s, ok := settings[types.SettingEnabledSeverities]
	if !ok || s == nil || !s.Changed || s.Value == nil {
		return
	}

	var sf *types.SeverityFilter
	// Handle both direct struct and JSON map from unmarshaling
	switch v := s.Value.(type) {
	case map[string]interface{}:
		sf = &types.SeverityFilter{}
		if critical, ok := v["critical"].(bool); ok {
			sf.Critical = critical
		}
		if high, ok := v["high"].(bool); ok {
			sf.High = high
		}
		if medium, ok := v["medium"].(bool); ok {
			sf.Medium = medium
		}
		if low, ok := v["low"].(bool); ok {
			sf.Low = low
		}
	}
	if sf == nil {
		return
	}

	conf := c.Engine().GetConfiguration()
	oldValue := config.GetFilterSeverity(conf)
	modified := config.SetSeverityFilterOnConfig(conf, sf, c.Logger())
	if !modified {
		return
	}
	propagations[types.SettingEnabledSeverities] = sf
	sendDiagnosticsForNewSettings(c)
	if c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingIsLspInitialized)) {
		analytics.SendAnalyticsForFields(c, "filterSeverity", &oldValue, sf, triggerSource, map[string]func(*types.SeverityFilter) any{
			"Critical": func(s *types.SeverityFilter) any { return s.Critical },
			"High":     func(s *types.SeverityFilter) any { return s.High },
			"Medium":   func(s *types.SeverityFilter) any { return s.Medium },
			"Low":      func(s *types.SeverityFilter) any { return s.Low },
		})
	}
}

func applyRiskScoreThreshold(c *config.Config, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, propagations map[string]any) {
	riskScore := settingIntPtr(settings, types.SettingRiskScoreThreshold)
	if riskScore == nil {
		return
	}
	conf := c.Engine().GetConfiguration()
	key := configuration.UserGlobalKey(types.SettingRiskScoreThreshold)
	oldValue := conf.GetInt(key)
	modified := oldValue != *riskScore
	conf.Set(key, *riskScore)
	if !modified {
		return
	}
	propagations[types.SettingRiskScoreThreshold] = *riskScore
	sendDiagnosticsForNewSettings(c)
	if c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingIsLspInitialized)) {
		analytics.SendConfigChangedAnalytics(c, "riskScoreThreshold", oldValue, *riskScore, triggerSource)
	}
}

func applyIssueViewOptions(c *config.Config, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, propagations map[string]any) {
	openPresent := settingPresent(settings, types.SettingIssueViewOpenIssues)
	ignoredPresent := settingPresent(settings, types.SettingIssueViewIgnoredIssues)
	if !openPresent && !ignoredPresent {
		return
	}

	ivo := &types.IssueViewOptions{}
	if v, ok := settingBool(settings, types.SettingIssueViewOpenIssues); ok {
		ivo.OpenIssues = v
	}
	if v, ok := settingBool(settings, types.SettingIssueViewIgnoredIssues); ok {
		ivo.IgnoredIssues = v
	}

	oldValue := config.GetIssueViewOptions(c.Engine().GetConfiguration())
	modified := config.SetIssueViewOptionsOnConfig(c.Engine().GetConfiguration(), ivo, c.Logger())
	if !modified {
		return
	}
	propagations[types.SettingIssueViewOpenIssues] = ivo.OpenIssues
	propagations[types.SettingIssueViewIgnoredIssues] = ivo.IgnoredIssues
	sendDiagnosticsForNewSettings(c)
	if c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingIsLspInitialized)) {
		analytics.SendAnalyticsForFields(c, "issueViewOptions", &oldValue, ivo, triggerSource, map[string]func(*types.IssueViewOptions) any{
			"OpenIssues":    func(s *types.IssueViewOptions) any { return s.OpenIssues },
			"IgnoredIssues": func(s *types.IssueViewOptions) any { return s.IgnoredIssues },
		})
	}
}

func applyDeltaFindings(c *config.Config, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, propagations map[string]any) {
	v, ok := settingBool(settings, types.SettingScanNetNew)
	if !ok {
		return
	}
	conf := c.Engine().GetConfiguration()
	oldValue := conf.GetBool(configuration.UserGlobalKey(types.SettingScanNetNew))
	modified := oldValue != v
	conf.Set(configuration.UserGlobalKey(types.SettingScanNetNew), v)
	if !modified {
		return
	}
	propagations[types.SettingScanNetNew] = v
	if c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingIsLspInitialized)) {
		sendDiagnosticsForNewSettings(c)
		analytics.SendConfigChangedAnalytics(c, configEnableDeltaFindings, oldValue, v, triggerSource)
	}
}

func applyAutoScan(c *config.Config, settings map[string]*types.ConfigSetting, propagations map[string]any) {
	// Auto scan true by default unless explicitly disabled
	var autoScan bool
	if v, ok := settingStr(settings, types.SettingScanAutomatic); ok {
		autoScan = v != "manual"
	} else if b, bOk := settingBool(settings, types.SettingScanAutomatic); bOk {
		autoScan = b
	} else {
		return
	}
	c.Engine().GetConfiguration().Set(configuration.UserGlobalKey(types.SettingScanAutomatic), autoScan)
	propagations[types.SettingScanAutomatic] = autoScan
}

func applyOrganization(c *config.Config, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource) {
	v, ok := settingStr(settings, types.SettingOrganization)
	if !ok {
		return
	}
	newOrg := strings.TrimSpace(v)
	oldOrgId := c.Engine().GetConfiguration().GetString(configuration.ORGANIZATION)
	config.SetOrganization(c.Engine().GetConfiguration(), newOrg)
	newOrgId := c.Engine().GetConfiguration().GetString(configuration.ORGANIZATION)
	if oldOrgId != newOrgId && c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingIsLspInitialized)) {
		analytics.SendConfigChangedAnalytics(c, configOrganization, oldOrgId, newOrgId, triggerSource)
	}
}

func applyCliConfig(c *config.Config, settings map[string]*types.ConfigSetting) {
	conf := c.Engine().GetConfiguration()
	if v, ok := settingBool(settings, types.SettingProxyInsecure); ok {
		conf.Set(configuration.UserGlobalKey(types.SettingCliInsecure), v)
		conf.Set(configuration.INSECURE_HTTPS, v)
	}
	if v, ok := settingStr(settings, types.SettingAdditionalParameters); ok {
		conf.Set(configuration.UserGlobalKey(types.SettingCliAdditionalOssParameters), strings.Split(v, " "))
	}
	if v, ok := settingStr(settings, types.SettingCliPath); ok {
		conf.Set(configuration.UserGlobalKey(types.SettingCliPath), strings.TrimSpace(v))
	}
}

func applyCliBaseDownloadURL(c *config.Config, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource) {
	v, ok := settingStr(settings, types.SettingBinaryBaseUrl)
	if !ok {
		return
	}
	conf := c.Engine().GetConfiguration()
	newURL := strings.TrimSpace(v)
	oldURL := conf.GetString(configuration.UserGlobalKey(types.SettingBinaryBaseUrl))
	conf.Set(configuration.UserGlobalKey(types.SettingBinaryBaseUrl), newURL)
	if oldURL != newURL && c.Engine().GetConfiguration().GetBool(configuration.UserGlobalKey(types.SettingIsLspInitialized)) {
		analytics.SendConfigChangedAnalytics(c, configCliBaseDownloadURL, oldURL, newURL, triggerSource)
	}
}

func applyErrorReporting(c *config.Config, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource) {
	v, ok := settingBool(settings, types.SettingSendErrorReports)
	if !ok {
		return
	}
	conf := c.Engine().GetConfiguration()
	key := configuration.UserGlobalKey(types.SettingSendErrorReports)
	oldValue := conf.GetBool(key)
	conf.Set(key, v)
	if oldValue != v && conf.GetBool(configuration.UserGlobalKey(types.SettingIsLspInitialized)) {
		analytics.SendConfigChangedAnalytics(c, configSendErrorReports, oldValue, v, triggerSource)
	}
}

func applyManageBinariesAutomatically(c *config.Config, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource) {
	v, ok := settingBool(settings, types.SettingAutomaticDownload)
	if !ok {
		return
	}
	conf := c.Engine().GetConfiguration()
	key := configuration.UserGlobalKey(types.SettingAutomaticDownload)
	oldValue := conf.GetBool(key)
	conf.Set(key, v)
	if oldValue != v && conf.GetBool(configuration.UserGlobalKey(types.SettingIsLspInitialized)) {
		analytics.SendConfigChangedAnalytics(c, configManageBinariesAutomatically, oldValue, v, triggerSource)
	}
}

func applyTrustedFoldersFromSettings(c *config.Config, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource) {
	if v, ok := settingBool(settings, types.SettingTrustEnabled); ok {
		conf := c.Engine().GetConfiguration()
		key := configuration.UserGlobalKey(types.SettingTrustEnabled)
		oldValue := conf.GetBool(key)
		conf.Set(key, v)
		if oldValue != v && conf.GetBool(configuration.UserGlobalKey(types.SettingIsLspInitialized)) {
			analytics.SendConfigChangedAnalytics(c, configEnableTrustedFoldersFeature, oldValue, v, triggerSource)
		}
	}
}

func applyTrustedFolders(c *config.Config, folders []string, triggerSource analytics.TriggerSource) {
	if folders == nil {
		return
	}
	conf := c.Engine().GetConfiguration()
	key := configuration.UserGlobalKey(types.SettingTrustedFolders)
	oldVal, _ := conf.Get(key).([]types.FilePath)
	var trustedFolders []types.FilePath
	for _, folder := range folders {
		trustedFolders = append(trustedFolders, types.FilePath(folder))
	}
	conf.Set(key, trustedFolders)
	if !util.SlicesEqualIgnoringOrder(oldVal, trustedFolders) && conf.GetBool(configuration.UserGlobalKey(types.SettingIsLspInitialized)) {
		oldFoldersJSON, _ := json.Marshal(oldVal)
		newFoldersJSON, _ := json.Marshal(trustedFolders)
		go analytics.SendConfigChangedAnalyticsEvent(c, "trustedFolder", string(oldFoldersJSON), string(newFoldersJSON), types.FilePath(""), triggerSource)
	}
}

func applyPathToEnv(c *config.Config, path string) {
	logger := c.Logger().With().Str("method", "applyPathToEnv").Logger()
	conf := c.Engine().GetConfiguration()
	conf.Set(configuration.UserGlobalKey(types.SettingUserSettingsPath), path)

	if conf.GetBool(configuration.UserGlobalKey(types.SettingIsLspInitialized)) || !c.IsDefaultEnvReady() {
		return
	}

	cachedPath := conf.GetString(configuration.UserGlobalKey(types.SettingCachedOriginalPath))
	var newPath string
	if len(path) > 0 {
		_ = os.Unsetenv("Path")
		logger.Debug().Msg("adding configured path to PATH")
		newPath = path + string(os.PathListSeparator) + cachedPath
	} else {
		logger.Debug().Msg("restoring initial path")
		newPath = cachedPath
	}

	err := os.Setenv("PATH", newPath)
	if err != nil {
		logger.Err(err).Msgf("couldn't add path %s", path)
	}
	logger.Debug().Msgf("new PATH is '%s'", os.Getenv("PATH"))
}

func applySnykLearnCodeActions(c *config.Config, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource) {
	v, ok := settingBool(settings, types.SettingEnableSnykLearnCodeActions)
	if !ok {
		return
	}
	conf := c.Engine().GetConfiguration()
	key := configuration.UserGlobalKey(types.SettingEnableSnykLearnCodeActions)
	oldValue := conf.GetBool(key)
	conf.Set(key, v)
	if oldValue != v && conf.GetBool(configuration.UserGlobalKey(types.SettingIsLspInitialized)) {
		analytics.SendConfigChangedAnalytics(c, configEnableSnykLearnCodeActions, oldValue, v, triggerSource)
	}
}

func applySnykOssQuickFixCodeActions(c *config.Config, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource) {
	v, ok := settingBool(settings, types.SettingEnableSnykOssQuickFixActions)
	if !ok {
		return
	}
	conf := c.Engine().GetConfiguration()
	key := configuration.UserGlobalKey(types.SettingEnableSnykOssQuickFixActions)
	oldValue := conf.GetBool(key)
	conf.Set(key, v)
	if oldValue != v && conf.GetBool(configuration.UserGlobalKey(types.SettingIsLspInitialized)) {
		analytics.SendConfigChangedAnalytics(c, configEnableSnykOSSQuickFixCodeActions, oldValue, v, triggerSource)
	}
}

func applySnykOpenBrowserActions(c *config.Config, settings map[string]*types.ConfigSetting) {
	if v, ok := settingBool(settings, types.SettingEnableSnykOpenBrowserActions); ok {
		c.Engine().GetConfiguration().Set(configuration.UserGlobalKey(types.SettingEnableSnykOpenBrowserActions), v)
	}
}

func applyMcpConfiguration(c *config.Config, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource) {
	n := di.Notifier()
	if v, ok := settingBool(settings, types.SettingAutoConfigureMcpServer); ok {
		conf := c.Engine().GetConfiguration()
		key := configuration.UserGlobalKey(types.SettingAutoConfigureMcpServer)
		oldValue := conf.GetBool(key)
		conf.Set(key, v)
		if oldValue != v {
			if conf.GetBool(configuration.UserGlobalKey(types.SettingIsLspInitialized)) {
				go analytics.SendConfigChangedAnalytics(c, configAutoConfigureSnykMcpServer, oldValue, v, triggerSource)
			}
			mcpWorkflow.CallMcpConfigWorkflow(c, n, true, false)
		}
	}

	if v, ok := settingStr(settings, types.SettingSecureAtInceptionExecutionFreq); ok {
		conf := c.Engine().GetConfiguration()
		key := configuration.UserGlobalKey(types.SettingSecureAtInceptionExecutionFreq)
		oldValue := conf.GetString(key)
		conf.Set(key, v)
		if oldValue != v {
			if conf.GetBool(configuration.UserGlobalKey(types.SettingIsLspInitialized)) {
				go analytics.SendConfigChangedAnalytics(c, configSecureAtInceptionExecutionFrequency, oldValue, v, triggerSource)
			}
			mcpWorkflow.CallMcpConfigWorkflow(c, n, false, true)
		}
	}
}

func applyProxyConfig(c *config.Config, settings map[string]*types.ConfigSetting) {
	conf := c.Engine().GetConfiguration()
	if v, ok := settingStr(settings, types.SettingProxyHttp); ok && v != "" {
		conf.Set(configuration.UserGlobalKey(types.SettingProxyHttp), v)
	}
	if v, ok := settingStr(settings, types.SettingProxyHttps); ok && v != "" {
		conf.Set(configuration.UserGlobalKey(types.SettingProxyHttps), v)
	}
	if v, ok := settingStr(settings, types.SettingProxyNoProxy); ok && v != "" {
		conf.Set(configuration.UserGlobalKey(types.SettingProxyNoProxy), v)
	}
}

func applyEnvironment(c *config.Config, settings map[string]*types.ConfigSetting) {
	v, ok := settingStr(settings, types.SettingAdditionalEnvironment)
	if !ok || v == "" {
		return
	}
	envVars := strings.Split(v, ";")
	for _, envVar := range envVars {
		parts := strings.SplitN(envVar, "=", 2)
		if len(parts) != 2 {
			continue
		}
		err := os.Setenv(parts[0], parts[1])
		if err != nil {
			c.Logger().Err(err).Msgf("couldn't set env variable %s", envVar)
		}
	}
}

func applyCodeEndpoint(c *config.Config, settings map[string]*types.ConfigSetting) {
	if v, ok := settingStr(settings, types.SettingCodeEndpoint); ok && v != "" {
		c.Engine().GetConfiguration().Set(configuration.UserGlobalKey(types.SettingCodeEndpoint), strings.TrimSpace(v))
	}
}

func applyPublishSecurityAtInceptionRules(c *config.Config, settings map[string]*types.ConfigSetting) {
	if v, ok := settingBool(settings, types.SettingPublishSecurityAtInceptionRules); ok {
		c.Engine().GetConfiguration().Set(configuration.UserGlobalKey(types.SettingPublishSecurityAtInceptionRules), v)
	}
}

func applyCliReleaseChannel(c *config.Config, settings map[string]*types.ConfigSetting) {
	if v, ok := settingStr(settings, types.SettingCliReleaseChannel); ok && v != "" {
		c.Engine().GetConfiguration().Set(configuration.UserGlobalKey(types.SettingCliReleaseChannel), strings.TrimSpace(v))
	}
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
// - For *LocalConfigField: nil = don't change, Changed+Value = set, Changed+nil = reset
// It loads the existing FolderConfig (read-only), applies the LspFolderConfig updates, and returns
// the processed config without persisting. The caller is responsible for batch-persisting all changes.
// Returns: (processedConfig, oldSnapshot, newSnapshot, configChanged)
func processSingleLspFolderConfig(c *config.Config, path types.FilePath, incomingMap map[types.FilePath]types.LspFolderConfig, notifier notification.Notifier) (types.FolderConfig, types.FolderConfigSnapshot, types.FolderConfigSnapshot, bool) {
	logger := c.Logger().With().Str("method", "processSingleLspFolderConfig").Str("path", string(path)).Logger()
	prefixKeyConfig := c.Engine().GetConfiguration()

	// Read-only load: no writes to storage
	storedConfig := config.GetImmutableFolderConfigFromEngine(c.Engine(), c.GetConfigResolver(), path, c.Logger())

	// Capture old snapshot BEFORE applying updates
	oldSnapshot := types.ReadFolderConfigSnapshot(prefixKeyConfig, types.PathKey(path))

	// Start with existing stored config or create new
	var folderConfig types.FolderConfig
	if storedConfig != nil {
		folderConfig = *storedConfig
	} else {
		folderConfig = types.FolderConfig{FolderPath: path}
	}

	// Set ConfigResolver and Engine so ApplyLspUpdate writes to prefix keys
	folderConfig.Engine = c.Engine()
	if resolver := di.ConfigResolver(); resolver != nil {
		folderConfig.ConfigResolver = resolver
	}

	// Validate that the changes are allowed, then apply the new config.
	normalizedPath := types.PathKey(path)
	applyChanged := false
	if incoming, hasIncoming := incomingMap[normalizedPath]; hasIncoming {
		hasLockedFieldRejections := validateLockedFields(c, &folderConfig, &incoming, &logger)
		if hasLockedFieldRejections {
			folderName := filepath.Base(string(folderConfig.FolderPath))
			notifier.SendShowMessage(sglsp.MTWarning,
				fmt.Sprintf("Failed to update %s: Some settings are locked by your organization's policy", folderName))
		}

		applyChanged = folderConfig.ApplyLspUpdate(&incoming)
	}

	updateFolderOrgIfNeeded(c, path, storedConfig, &folderConfig, oldSnapshot, notifier)
	di.FeatureFlagService().PopulateFolderConfig(&folderConfig)

	newSnapshot := types.ReadFolderConfigSnapshot(prefixKeyConfig, normalizedPath)
	configChanged := storedConfig == nil || applyChanged

	return folderConfig, oldSnapshot, newSnapshot, configChanged
}

// validateLockedFields checks if any fields in the incoming LspFolderConfig are locked by LDX-Sync.
// Returns true if any fields were rejected due to being locked.
// If the incoming update changes PreferredOrg, locks are evaluated against the NEW org's policies
// to prevent bypassing stricter locks during an org switch.
func validateLockedFields(c *config.Config, folderConfig *types.FolderConfig, incoming *types.LspFolderConfig, logger *zerolog.Logger) bool {
	resolver := di.ConfigResolver()
	if resolver == nil || incoming.Settings == nil {
		return false
	}

	// If the incoming update changes PreferredOrg, evaluate locks against the new org.
	configForValidation := folderConfig
	if preferredOrg, ok := incoming.Settings[types.SettingPreferredOrg]; ok && preferredOrg != nil && preferredOrg.Value != nil {
		if newOrg, ok := preferredOrg.Value.(string); ok && newOrg != folderConfig.PreferredOrg() {
			// Sync org to configuration so ConfigResolver.getEffectiveOrg reads the new org
			if prefixKeyConf := c.Engine().GetConfiguration(); prefixKeyConf != nil {
				folderPath := string(types.PathKey(configForValidation.GetFolderPath()))
				if folderPath != "" {
					prefixKeyConf.Set(configuration.UserFolderKey(folderPath, types.SettingOrgSetByUser), &configuration.LocalConfigField{Value: true, Changed: true})
					prefixKeyConf.Set(configuration.UserFolderKey(folderPath, types.SettingPreferredOrg), &configuration.LocalConfigField{Value: newOrg, Changed: true})
				}
			}
			configForValidation = folderConfig
		}
	}

	updatesRejected := false
	for settingName, cs := range incoming.Settings {
		if cs == nil || !cs.Changed {
			continue
		}
		if !types.IsOrgScopedSetting(settingName) {
			continue
		}
		if resolver.IsLocked(settingName, configForValidation) {
			logger.Info().
				Str("setting", settingName).
				Msg("Rejecting change to locked setting - locked by organization policy")
			updatesRejected = true
			delete(incoming.Settings, settingName)
		}
	}

	return updatesRejected
}

func updateFolderOrgIfNeeded(c *config.Config, path types.FilePath, storedConfig *types.FolderConfig, folderConfig *types.FolderConfig, oldSnapshot types.FolderConfigSnapshot, notifier notification.Notifier) {
	orgSettingsChanged := storedConfig != nil && !folderConfigsOrgSettingsEqual(oldSnapshot, *folderConfig)

	if orgSettingsChanged {
		updateFolderConfigOrg(c, storedConfig, folderConfig)
		folder := c.Workspace().GetFolderContaining(folderConfig.FolderPath)
		if folder != nil {
			di.LdxSyncService().RefreshConfigFromLdxSync(context.Background(), c, []types.Folder{folder}, notifier)
		}
		return
	}

	// No explicit org change from client; inherit global org for folders that have no org setup yet
	if oldSnapshot.PreferredOrg == "" && !oldSnapshot.OrgSetByUser && c.Engine().GetConfiguration().GetString(configuration.ORGANIZATION) != "" {
		types.SetPreferredOrgAndOrgSetByUser(c.Engine().GetConfiguration(), types.PathKey(path), c.Engine().GetConfiguration().GetString(configuration.ORGANIZATION), false)
	}
}

func handleFolderCacheClearing(c *config.Config, path types.FilePath, oldSnapshot, newSnapshot types.FolderConfigSnapshot, logger *zerolog.Logger, triggerSource analytics.TriggerSource) {
	baseBranchChanged := oldSnapshot.BaseBranch != newSnapshot.BaseBranch
	referenceFolderChanged := oldSnapshot.ReferenceFolderPath != newSnapshot.ReferenceFolderPath

	if baseBranchChanged || referenceFolderChanged {
		logger.Info().
			Str("folderPath", string(path)).
			Str("oldBaseBranch", oldSnapshot.BaseBranch).
			Str("newBaseBranch", newSnapshot.BaseBranch).
			Str("oldReferenceFolderPath", string(oldSnapshot.ReferenceFolderPath)).
			Str("newReferenceFolderPath", string(newSnapshot.ReferenceFolderPath)).
			Msg("base branch or reference folder changed, clearing persisted scan cache for folder")

		ws := c.Workspace()
		if ws != nil {
			ws.GetScanSnapshotClearerExister().ClearFolder(path)
		}
	}

	sendFolderConfigAnalytics(c, path, triggerSource, oldSnapshot, newSnapshot)
}

func sendFolderConfigUpdateIfNeeded(c *config.Config, notifier notification.Notifier, folderConfigs []types.FolderConfig, needsToSendUpdate bool, triggerSource analytics.TriggerSource) {
	// Don't send folder configs on initialize, since initialized will always send them.
	if needsToSendUpdate && triggerSource != analytics.TriggerSourceInitialize {
		lspConfig := command.BuildLspConfiguration(c, nil, di.ConfigResolver())
		notifier.Send(lspConfig)
	}
}

func sendFolderConfigAnalytics(c *config.Config, path types.FilePath, triggerSource analytics.TriggerSource, oldSnapshot, newSnapshot types.FolderConfigSnapshot) {
	// BaseBranch change
	if oldSnapshot.BaseBranch != newSnapshot.BaseBranch {
		go analytics.SendConfigChangedAnalyticsEvent(c, configBaseBranch, oldSnapshot.BaseBranch, newSnapshot.BaseBranch, path, triggerSource)
	}

	// AdditionalParameters change
	if !util.SlicesEqualIgnoringOrder(oldSnapshot.AdditionalParameters, newSnapshot.AdditionalParameters) {
		oldParamsJSON, _ := json.Marshal(oldSnapshot.AdditionalParameters)
		newParamsJSON, _ := json.Marshal(newSnapshot.AdditionalParameters)
		go analytics.SendConfigChangedAnalyticsEvent(c, configAdditionalParameters, string(oldParamsJSON), string(newParamsJSON), path, triggerSource)
	}

	// ReferenceFolderPath change
	if oldSnapshot.ReferenceFolderPath != newSnapshot.ReferenceFolderPath {
		go analytics.SendConfigChangedAnalyticsEvent(c, configReferenceFolderPath, oldSnapshot.ReferenceFolderPath, newSnapshot.ReferenceFolderPath, path, triggerSource)
	}

	// ScanCommandConfig change
	if !reflect.DeepEqual(oldSnapshot.ScanCommandConfig, newSnapshot.ScanCommandConfig) {
		oldConfigJSON, _ := json.Marshal(oldSnapshot.ScanCommandConfig)
		newConfigJSON, _ := json.Marshal(newSnapshot.ScanCommandConfig)
		go analytics.SendConfigChangedAnalyticsEvent(c, configScanCommandConfig, string(oldConfigJSON), string(newConfigJSON), path, triggerSource)
	}

	// PreferredOrg change
	if oldSnapshot.PreferredOrg != newSnapshot.PreferredOrg && newSnapshot.PreferredOrg != "" {
		go analytics.SendConfigChangedAnalyticsEvent(c, configPreferredOrg, oldSnapshot.PreferredOrg, newSnapshot.PreferredOrg, path, triggerSource)
	}

	// OrgSetByUser change
	if oldSnapshot.OrgSetByUser != newSnapshot.OrgSetByUser {
		go analytics.SendConfigChangedAnalyticsEvent(c, configOrgSetByUser, oldSnapshot.OrgSetByUser, newSnapshot.OrgSetByUser, path, triggerSource)
	}
}

// folderConfigsOrgSettingsEqual compares the pre-update snapshot with the current configuration state for the folder.
// Uses oldSnapshot (captured before ApplyLspUpdate) because after ApplyLspUpdate both folderConfig and storedConfig
// would read the same configuration keys and appear equal even when the incoming update changed org settings.
func folderConfigsOrgSettingsEqual(oldSnapshot types.FolderConfigSnapshot, folderConfig types.FolderConfig) bool {
	conf := folderConfig.Conf()
	if conf == nil {
		return false
	}
	currentSnap := types.ReadFolderConfigSnapshot(conf, folderConfig.FolderPath)
	return oldSnapshot.PreferredOrg == currentSnap.PreferredOrg &&
		oldSnapshot.OrgSetByUser == currentSnap.OrgSetByUser &&
		oldSnapshot.AutoDeterminedOrg == currentSnap.AutoDeterminedOrg
}

func updateFolderConfigOrg(c *config.Config, storedConfig *types.FolderConfig, folderConfig *types.FolderConfig) {
	prefixKeyConfig := c.Engine().GetConfiguration()
	folderSnap := types.ReadFolderConfigSnapshot(prefixKeyConfig, folderConfig.FolderPath)

	// Ensure AutoDeterminedOrg is populated from cache or stored config
	if folderSnap.AutoDeterminedOrg == "" {
		if storedConfig != nil {
			storedSnap := types.ReadFolderConfigSnapshot(prefixKeyConfig, storedConfig.FolderPath)
			if storedSnap.AutoDeterminedOrg != "" {
				types.SetAutoDeterminedOrg(prefixKeyConfig, folderConfig.FolderPath, storedSnap.AutoDeterminedOrg)
			}
		}
		cache := c.GetLdxSyncOrgConfigCache()
		if orgId := cache.GetOrgIdForFolder(folderConfig.FolderPath); orgId != "" {
			types.SetAutoDeterminedOrg(prefixKeyConfig, folderConfig.FolderPath, orgId)
		}
	}

	if storedConfig == nil {
		return
	}

	storedSnap := types.ReadFolderConfigSnapshot(prefixKeyConfig, storedConfig.FolderPath)
	orgSetByUserJustChanged := folderSnap.OrgSetByUser != storedSnap.OrgSetByUser
	orgHasJustChanged := folderSnap.PreferredOrg != storedSnap.PreferredOrg
	if orgSetByUserJustChanged {
		if !folderSnap.OrgSetByUser {
			types.SetPreferredOrgAndOrgSetByUser(prefixKeyConfig, folderConfig.FolderPath, "", false)
		}
	} else if orgHasJustChanged {
		inheritedFromGlobal := storedSnap.PreferredOrg == "" && folderSnap.PreferredOrg != "" && !folderSnap.OrgSetByUser
		if !inheritedFromGlobal {
			types.SetPreferredOrgAndOrgSetByUser(prefixKeyConfig, folderConfig.FolderPath, folderSnap.PreferredOrg, true)
		}
	} else if !folderSnap.OrgSetByUser {
		types.SetPreferredOrgAndOrgSetByUser(prefixKeyConfig, folderConfig.FolderPath, "", false)
	}
}

func sendDiagnosticsForNewSettings(c *config.Config) {
	ws := c.Workspace()
	if ws == nil {
		return
	}
	go ws.HandleConfigChange()
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
	prefixKeyConfig := c.Engine().GetConfiguration()
	cache := c.GetLdxSyncOrgConfigCache()

	ws := c.Workspace()
	if ws == nil {
		logger.Debug().Msg("No workspace, skipping override clearing")
		return
	}

	for _, folder := range ws.Folders() {
		folderPath := folder.Path()
		clearFolderOverridesForSettings(folderPath, orgScopedNames, cache, prefixKeyConfig, &logger)
	}

	logger.Debug().Int("settingCount", len(orgScopedNames)).Msg("Processed workspace folders for clearing overrides on global change")
}

func clearFolderOverridesForSettings(folderPath types.FilePath, settingNames []string, cache *types.LDXSyncConfigCache, prefixKeyConfig configuration.Configuration, logger *zerolog.Logger) bool {
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

		if types.HasUserOverride(prefixKeyConfig, folderPath, settingName) {
			key := configuration.UserFolderKey(string(types.PathKey(folderPath)), settingName)
			prefixKeyConfig.Unset(key)
			cleared = true
			logger.Debug().
				Str("folder", string(folderPath)).
				Str("setting", settingName).
				Msg("Cleared folder override so global value takes effect")
		}
	}
	return cleared
}
