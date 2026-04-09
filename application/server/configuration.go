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
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/internal/folderconfig"
	mcpWorkflow "github.com/snyk/snyk-ls/internal/mcp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/infrastructure/analytics"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
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

func workspaceDidChangeConfiguration(conf configuration.Configuration, srv *jrpc2.Server) jrpc2.Handler {
	return handler.New(func(ctx context.Context, params types.DidChangeConfigurationParams) (bool, error) {
		logger := ctx2.LoggerFromContext(ctx)
		engine, _ := ctx2.EngineFromContext(ctx)
		defer logger.Info().Str("method", "WorkspaceDidChangeConfiguration").Msg("DONE")

		if len(params.Settings.Settings) > 0 || len(params.Settings.FolderConfigs) > 0 {
			return handlePushModel(conf, engine, logger, params.Settings)
		}

		return handlePullModel(conf, engine, logger, srv, ctx)
	})
}

func handlePushModel(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, params types.LspConfigurationParam) (bool, error) {
	triggerSource := analytics.TriggerSourceIDE
	if !conf.GetBool(types.SettingIsLspInitialized) {
		triggerSource = analytics.TriggerSourceInitialize
	}
	UpdateSettings(conf, engine, logger, params.Settings, params.FolderConfigs, triggerSource, di.ConfigResolver())
	return true, nil
}

func handlePullModel(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, srv *jrpc2.Server, ctx context.Context) (bool, error) {
	key := types.SettingClientCapabilities
	capabilities, ok := conf.Get(key).(types.ClientCapabilities)
	if !ok {
		capabilities = types.ClientCapabilities{}
	}
	if !capabilities.Workspace.Configuration {
		logger.Debug().Msg("Pull model for workspace configuration not supported, ignoring workspace/didChangeConfiguration notification.")
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
	if len(fetched.Settings.Settings) == 0 && len(fetched.Settings.FolderConfigs) == 0 {
		return false, nil
	}

	triggerSource := analytics.TriggerSourceIDE
	if !conf.GetBool(types.SettingIsLspInitialized) {
		triggerSource = analytics.TriggerSourceInitialize
	}
	UpdateSettings(conf, engine, logger, fetched.Settings.Settings, fetched.Settings.FolderConfigs, triggerSource, di.ConfigResolver())
	return true, nil
}

// processInitMetadata handles init-only metadata fields from InitializationOptions.
func processInitMetadata(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, opts types.InitializationOptions) {
	conf.Set(configresolver.UserGlobalKey(types.SettingClientProtocolVersion), opts.RequiredProtocolVersion) // TODO must be internal

	if opts.DeviceId != "" {
		conf.Set(configresolver.UserGlobalKey(types.SettingDeviceId), strings.TrimSpace(opts.DeviceId))
	}
	conf.Set(configresolver.UserGlobalKey(types.SettingOsArch), opts.OsArch)
	conf.Set(configresolver.UserGlobalKey(types.SettingOsPlatform), opts.OsPlatform)
	conf.Set(configresolver.UserGlobalKey(types.SettingRuntimeVersion), opts.RuntimeVersion)
	conf.Set(configresolver.UserGlobalKey(types.SettingRuntimeName), opts.RuntimeName)

	if opts.HoverVerbosity != nil {
		conf.Set(configresolver.UserGlobalKey(types.SettingHoverVerbosity), *opts.HoverVerbosity)
	}
	if opts.OutputFormat != nil {
		conf.Set(configresolver.UserGlobalKey(types.SettingFormat), *opts.OutputFormat)
	}

	autoAuth := true
	if v, ok := settingBool(opts.Settings, types.SettingAutomaticAuthentication); ok {
		autoAuth = v
	}
	conf.Set(configresolver.UserGlobalKey(types.SettingAutomaticAuthentication), autoAuth)

	applyPathToEnv(conf, logger, opts.Path)
	applyTrustedFolders(conf, engine, logger, opts.TrustedFolders, analytics.TriggerSourceInitialize, di.ConfigResolver())

	// Auto scan true by default unless explicitly disabled
	autoScan := true
	if v, ok := settingStr(opts.Settings, types.SettingScanAutomatic); ok && v == "manual" {
		autoScan = false
	} else if b, bOk := settingBool(opts.Settings, types.SettingScanAutomatic); bOk {
		autoScan = b
	}
	conf.Set(configresolver.UserGlobalKey(types.SettingScanAutomatic), autoScan)
}

// InitializeSettings processes settings from the LSP initialize request.
// Only settings explicitly marked Changed by the IDE are applied; IDE defaults
// (Changed=false) are left alone so they don't override ldx-sync or GAF defaults.
func InitializeSettings(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, opts types.InitializationOptions) {
	resolver := di.ConfigResolver()

	processInitMetadata(conf, engine, logger, opts)
	// global
	processConfigSettings(conf, engine, logger, opts.Settings, analytics.TriggerSourceInitialize, resolver)
	// folder
	processFolderConfigs(conf, engine, logger, opts.FolderConfigs, analytics.TriggerSourceInitialize, resolver)
}

// UpdateSettings processes settings from workspace/didChangeConfiguration.
func UpdateSettings(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, folderConfigs []types.LspFolderConfig, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
	ws := config.GetWorkspace(conf)
	oldToken := config.GetToken(conf)

	previousState := make(map[types.FilePath]map[product.FilterableIssueType]bool)
	if ws != nil {
		for _, folder := range ws.Folders() {
			previousState[folder.Path()] = folder.DisplayableIssueTypes()
		}
	}

	processConfigSettings(conf, engine, logger, settings, triggerSource, configResolver)
	processFolderConfigs(conf, engine, logger, folderConfigs, triggerSource, configResolver)

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

	refreshLdxSyncOnTokenChange(conf, engine, logger, ws, oldToken)
}

func refreshLdxSyncOnTokenChange(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, ws types.Workspace, oldToken string) {
	newToken := config.GetToken(conf)
	if newToken == oldToken || newToken == "" || ws == nil {
		return
	}
	folders := ws.Folders()
	if len(folders) == 0 {
		return
	}
	logger.Info().Msg("token changed via settings, refreshing LDX-Sync configuration")
	di.LdxSyncService().RefreshConfigFromLdxSync(context.Background(), conf, engine, logger, folders, di.Notifier())
}

// processConfigSettings writes incoming settings to configuration and applies side effects.
// This replaces the old writeSettings + update* functions.
func processConfigSettings(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
	conf.ClearCache()

	if len(settings) == 0 {
		return
	}

	propagations := make(map[string]any)

	applyApiEndpoints(conf, engine, logger, settings, triggerSource, configResolver)
	applyToken(conf, settings)
	applyAuthenticationMethod(conf, engine, logger, settings, triggerSource, configResolver)
	applyAutomaticAuthentication(conf, settings)
	applyProductEnablement(conf, engine, logger, settings, triggerSource, propagations, configResolver)
	applySeverityFilter(conf, engine, logger, settings, triggerSource, propagations, configResolver)
	applyRiskScoreThreshold(conf, engine, logger, settings, triggerSource, propagations, configResolver)
	applyIssueViewOptions(conf, engine, logger, settings, triggerSource, propagations, configResolver)
	applyDeltaFindings(conf, engine, logger, settings, triggerSource, propagations, configResolver)
	applyAutoScan(conf, settings, propagations)
	applyOrganization(conf, engine, logger, settings, triggerSource, configResolver)
	applyCliConfig(conf, settings)
	applyEnvironment(conf, logger, settings)
	applyCliBaseDownloadURL(conf, engine, logger, settings, triggerSource, configResolver)
	applyErrorReporting(conf, engine, logger, settings, triggerSource, configResolver)
	applyManageBinariesAutomatically(conf, engine, logger, settings, triggerSource, configResolver)
	applyTrustEnabledFromSettings(conf, engine, logger, settings, triggerSource, configResolver)
	applySnykLearnCodeActions(conf, engine, logger, settings, triggerSource, configResolver)
	applySnykOssQuickFixCodeActions(conf, engine, logger, settings, triggerSource, configResolver)
	applySnykOpenBrowserActions(conf, settings)
	applyMcpConfiguration(conf, engine, logger, settings, triggerSource, configResolver)
	applyPublishSecurityAtInceptionRules(conf, settings)
	// this is without function right now, we do not use/distribute proxy settings from/to IDEs
	applyProxyConfig(conf, settings)
	applyCodeEndpoint(conf, settings)
	applyCliReleaseChannel(conf, settings)
}

// processFolderConfigs handles the folder configuration portion of incoming settings.
func processFolderConfigs(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, folderConfigs []types.LspFolderConfig, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
	notifier := di.Notifier()
	incomingMap := buildIncomingLspConfigMap(folderConfigs)
	allPaths := gatherAllFolderPathsFromLspConfigs(incomingMap, config.GetWorkspace(conf))

	logger.Debug().
		Int("incomingFolderConfigCount", len(folderConfigs)).
		Int("incomingMapCount", len(incomingMap)).
		Int("allPathsCount", len(allPaths)).
		Msg("processFolderConfigs - processing folder configs")

	var processedConfigs []types.FolderConfig
	var changedConfigs []*types.FolderConfig

	for path := range allPaths {
		folderConfig, oldSnapshot, newSnapshot, configChanged := processSingleLspFolderConfig(conf, engine, logger, path, incomingMap, notifier)

		if configChanged {
			changedConfigs = append(changedConfigs, &folderConfig)
		}

		handleFolderCacheClearing(conf, engine, logger, path, oldSnapshot, newSnapshot, triggerSource, configResolver)
		processedConfigs = append(processedConfigs, folderConfig)
	}

	if len(changedConfigs) > 0 {
		if err := folderconfig.BatchUpdateFolderConfigs(conf, changedConfigs, logger); err != nil {
			logger.Err(err).Int("count", len(changedConfigs)).Msg("failed to batch update folder configs")
		}
	}

	sendFolderConfigUpdateIfNeeded(conf, engine, logger, notifier, processedConfigs, len(changedConfigs) > 0, triggerSource, configResolver)
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

func applyApiEndpoints(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
	v, ok := settingStr(settings, types.SettingApiEndpoint)
	if !ok {
		return
	}
	snykApiUrl := strings.TrimSpace(v)
	oldEndpoint := conf.GetString(configresolver.UserGlobalKey(types.SettingApiEndpoint))
	endpointsUpdated := command.ApplyEndpointChange(context.Background(), conf, di.AuthenticationService(), snykApiUrl)
	if endpointsUpdated && conf.GetBool(types.SettingIsLspInitialized) {
		analytics.SendConfigChangedAnalytics(conf, engine, logger, configEndpoint, oldEndpoint, snykApiUrl, triggerSource, configResolver)
	}
}

func applyToken(conf configuration.Configuration, settings map[string]*types.ConfigSetting) {
	if v, ok := settingStr(settings, types.SettingToken); ok && v != "" {
		di.AuthenticationService().UpdateCredentials(v, false, false)
	}
}

func applyAuthenticationMethod(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
	v, ok := settingStr(settings, types.SettingAuthenticationMethod)
	if !ok || types.AuthenticationMethod(v) == types.EmptyAuthenticationMethod {
		return
	}
	oldValue := config.GetAuthenticationMethodFromConfig(conf)
	command.ApplyAuthMethodChange(conf, di.AuthenticationService(), logger, types.AuthenticationMethod(v))
	if oldValue != types.AuthenticationMethod(v) && conf.GetBool(types.SettingIsLspInitialized) {
		analytics.SendConfigChangedAnalytics(conf, engine, logger, configAuthenticationMethod, oldValue, types.AuthenticationMethod(v), triggerSource, configResolver)
	}
}

func applyAutomaticAuthentication(conf configuration.Configuration, settings map[string]*types.ConfigSetting) {
	if v, ok := settingBool(settings, types.SettingAutomaticAuthentication); ok {
		conf.Set(configresolver.UserGlobalKey(types.SettingAutomaticAuthentication), v)
	}
}

func logIncomingProductSettings(logger *zerolog.Logger, settings map[string]*types.ConfigSetting) {
	for _, productKey := range []string{types.SettingSnykCodeEnabled, types.SettingSnykOssEnabled, types.SettingSnykIacEnabled, types.SettingSnykSecretsEnabled} {
		s, exists := settings[productKey]
		if exists && s != nil {
			logger.Debug().Str("setting", productKey).Bool("changed", s.Changed).Interface("value", s.Value).Msg("applyProductEnablement: incoming setting")
		} else {
			logger.Debug().Str("setting", productKey).Bool("exists", exists).Msg("applyProductEnablement: setting not in incoming map")
		}
	}
}

func applyProductEnablement(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, propagations map[string]any, configResolver types.ConfigResolverInterface) {
	lspInit := conf.GetBool(types.SettingIsLspInitialized)
	logIncomingProductSettings(logger, settings)
	if v, ok := settingBool(settings, types.SettingSnykCodeEnabled); ok {
		key := configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)
		oldValue := conf.GetBool(key)
		conf.Set(key, v)
		if oldValue != v {
			propagations[types.SettingSnykCodeEnabled] = v
			if lspInit {
				analytics.SendConfigChangedAnalytics(conf, engine, logger, configActivateSnykCode, oldValue, v, triggerSource, configResolver)
			}
		}
	}

	if v, ok := settingBool(settings, types.SettingSnykOssEnabled); ok {
		key := configresolver.UserGlobalKey(types.SettingSnykOssEnabled)
		oldValue := conf.GetBool(key)
		conf.Set(key, v)
		if oldValue != v {
			propagations[types.SettingSnykOssEnabled] = v
			if lspInit {
				analytics.SendConfigChangedAnalytics(conf, engine, logger, configActivateSnykOpenSource, oldValue, v, triggerSource, configResolver)
			}
		}
	}

	if v, ok := settingBool(settings, types.SettingSnykIacEnabled); ok {
		key := configresolver.UserGlobalKey(types.SettingSnykIacEnabled)
		oldValue := conf.GetBool(key)
		conf.Set(key, v)
		if oldValue != v {
			propagations[types.SettingSnykIacEnabled] = v
			if lspInit {
				analytics.SendConfigChangedAnalytics(conf, engine, logger, configActivateSnykIac, oldValue, v, triggerSource, configResolver)
			}
		}
	}

	if v, ok := settingBool(settings, types.SettingSnykSecretsEnabled); ok {
		key := configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled)
		oldValue := conf.GetBool(key)
		conf.Set(key, v)
		if oldValue != v {
			propagations[types.SettingSnykSecretsEnabled] = v
			if lspInit {
				analytics.SendConfigChangedAnalytics(conf, engine, logger, configActivateSnykSecrets, oldValue, v, triggerSource, configResolver)
			}
		}
	}
}

func applySeverityFilter(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, propagations map[string]any, configResolver types.ConfigResolverInterface) {
	s, ok := settings[types.SettingEnabledSeverities]
	if !ok || s == nil || !s.Changed || s.Value == nil {
		return
	}

	var sf *types.SeverityFilter
	switch v := s.Value.(type) {
	case *types.SeverityFilter:
		sf = v
	case types.SeverityFilter:
		sf = &v
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

	oldValue := config.GetFilterSeverity(conf)
	modified := config.SetSeverityFilterOnConfig(conf, sf, logger)
	if !modified {
		return
	}
	propagations[types.SettingEnabledSeverities] = sf
	sendDiagnosticsForNewSettings(conf, logger)
	if conf.GetBool(types.SettingIsLspInitialized) {
		analytics.SendAnalyticsForFields(conf, engine, logger, "filterSeverity", &oldValue, sf, triggerSource, map[string]func(*types.SeverityFilter) any{
			"Critical": func(s *types.SeverityFilter) any { return s.Critical },
			"High":     func(s *types.SeverityFilter) any { return s.High },
			"Medium":   func(s *types.SeverityFilter) any { return s.Medium },
			"Low":      func(s *types.SeverityFilter) any { return s.Low },
		}, configResolver)
	}
}

func applyRiskScoreThreshold(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, propagations map[string]any, configResolver types.ConfigResolverInterface) {
	riskScore := settingIntPtr(settings, types.SettingRiskScoreThreshold)
	if riskScore == nil {
		return
	}
	key := configresolver.UserGlobalKey(types.SettingRiskScoreThreshold)
	oldValue := conf.GetInt(key)
	modified := oldValue != *riskScore
	conf.Set(key, *riskScore)
	if !modified {
		return
	}
	propagations[types.SettingRiskScoreThreshold] = *riskScore
	sendDiagnosticsForNewSettings(conf, logger)
	if conf.GetBool(types.SettingIsLspInitialized) {
		analytics.SendConfigChangedAnalytics(conf, engine, logger, "riskScoreThreshold", oldValue, *riskScore, triggerSource, configResolver)
	}
}

func applyIssueViewOptions(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, propagations map[string]any, configResolver types.ConfigResolverInterface) {
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

	oldValue := config.GetIssueViewOptions(conf)
	modified := config.SetIssueViewOptionsOnConfig(conf, ivo, logger)
	if !modified {
		return
	}
	propagations[types.SettingIssueViewOpenIssues] = ivo.OpenIssues
	propagations[types.SettingIssueViewIgnoredIssues] = ivo.IgnoredIssues
	sendDiagnosticsForNewSettings(conf, logger)
	if conf.GetBool(types.SettingIsLspInitialized) {
		analytics.SendAnalyticsForFields(conf, engine, logger, "issueViewOptions", &oldValue, ivo, triggerSource, map[string]func(*types.IssueViewOptions) any{
			"OpenIssues":    func(s *types.IssueViewOptions) any { return s.OpenIssues },
			"IgnoredIssues": func(s *types.IssueViewOptions) any { return s.IgnoredIssues },
		}, configResolver)
	}
}

func applyDeltaFindings(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, propagations map[string]any, configResolver types.ConfigResolverInterface) {
	v, ok := settingBool(settings, types.SettingScanNetNew)
	if !ok {
		return
	}
	oldValue := conf.GetBool(configresolver.UserGlobalKey(types.SettingScanNetNew))
	modified := oldValue != v
	conf.Set(configresolver.UserGlobalKey(types.SettingScanNetNew), v)
	if !modified {
		return
	}
	propagations[types.SettingScanNetNew] = v
	if conf.GetBool(types.SettingIsLspInitialized) {
		sendDiagnosticsForNewSettings(conf, logger)
		analytics.SendConfigChangedAnalytics(conf, engine, logger, configEnableDeltaFindings, oldValue, v, triggerSource, configResolver)
	}
}

func applyAutoScan(conf configuration.Configuration, settings map[string]*types.ConfigSetting, propagations map[string]any) {
	// Auto scan true by default unless explicitly disabled
	var autoScan bool
	if v, ok := settingStr(settings, types.SettingScanAutomatic); ok {
		autoScan = v != "manual"
	} else if b, bOk := settingBool(settings, types.SettingScanAutomatic); bOk {
		autoScan = b
	} else {
		return
	}
	conf.Set(configresolver.UserGlobalKey(types.SettingScanAutomatic), autoScan)
	propagations[types.SettingScanAutomatic] = autoScan
}

func applyOrganization(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
	v, ok := settingStr(settings, types.SettingOrganization)
	if !ok {
		return
	}
	newOrg := strings.TrimSpace(v)
	oldOrgId := types.GetGlobalOrganization(conf)
	config.SetOrganization(conf, newOrg)
	newOrgId := types.GetGlobalOrganization(conf)
	if oldOrgId != newOrgId && conf.GetBool(types.SettingIsLspInitialized) {
		analytics.SendConfigChangedAnalytics(conf, engine, logger, configOrganization, oldOrgId, newOrgId, triggerSource, configResolver)
	}
}

func applyCliConfig(conf configuration.Configuration, settings map[string]*types.ConfigSetting) {
	if v, ok := settingBool(settings, types.SettingProxyInsecure); ok {
		conf.Set(configresolver.UserGlobalKey(types.SettingProxyInsecure), v)
		conf.Set(configuration.INSECURE_HTTPS, v)
	}
	if v, ok := settingStr(settings, types.SettingAdditionalParameters); ok {
		conf.Set(configresolver.UserGlobalKey(types.SettingCliAdditionalOssParameters), strings.Split(v, " "))
	}
	if v, ok := settingStr(settings, types.SettingCliPath); ok {
		conf.Set(configresolver.UserGlobalKey(types.SettingCliPath), strings.TrimSpace(v))
	}
}

func applyCliBaseDownloadURL(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
	v, ok := settingStr(settings, types.SettingBinaryBaseUrl)
	if !ok {
		return
	}
	newURL := strings.TrimSpace(v)
	oldURL := conf.GetString(configresolver.UserGlobalKey(types.SettingBinaryBaseUrl))
	conf.Set(configresolver.UserGlobalKey(types.SettingBinaryBaseUrl), newURL)
	if oldURL != newURL && conf.GetBool(types.SettingIsLspInitialized) {
		analytics.SendConfigChangedAnalytics(conf, engine, logger, configCliBaseDownloadURL, oldURL, newURL, triggerSource, configResolver)
	}
}

func applyErrorReporting(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
	v, ok := settingBool(settings, types.SettingSendErrorReports)
	if !ok {
		return
	}
	key := configresolver.UserGlobalKey(types.SettingSendErrorReports)
	oldValue := conf.GetBool(key)
	conf.Set(key, v)
	if oldValue != v && conf.GetBool(types.SettingIsLspInitialized) {
		analytics.SendConfigChangedAnalytics(conf, engine, logger, configSendErrorReports, oldValue, v, triggerSource, configResolver)
	}
}

func applyManageBinariesAutomatically(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
	v, ok := settingBool(settings, types.SettingAutomaticDownload)
	if !ok {
		return
	}
	key := configresolver.UserGlobalKey(types.SettingAutomaticDownload)
	oldValue := conf.GetBool(key)
	conf.Set(key, v)
	if oldValue != v && conf.GetBool(types.SettingIsLspInitialized) {
		analytics.SendConfigChangedAnalytics(conf, engine, logger, configManageBinariesAutomatically, oldValue, v, triggerSource, configResolver)
	}
}

func applyTrustEnabledFromSettings(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
	if v, ok := settingBool(settings, types.SettingTrustEnabled); ok {
		key := configresolver.UserGlobalKey(types.SettingTrustEnabled)
		oldValue := conf.GetBool(key)
		conf.Set(key, v)
		if oldValue != v && conf.GetBool(types.SettingIsLspInitialized) {
			analytics.SendConfigChangedAnalytics(conf, engine, logger, configEnableTrustedFoldersFeature, oldValue, v, triggerSource, configResolver)
		}
	}
}

func applyTrustedFolders(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, folders []string, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
	if folders == nil {
		return
	}
	key := configresolver.UserGlobalKey(types.SettingTrustedFolders)
	oldVal, _ := conf.Get(key).([]types.FilePath)
	var trustedFolders []types.FilePath
	for _, folder := range folders {
		trustedFolders = append(trustedFolders, types.FilePath(folder))
	}
	conf.Set(key, trustedFolders)
	if !util.SlicesEqualIgnoringOrder(oldVal, trustedFolders) && conf.GetBool(types.SettingIsLspInitialized) {
		oldFoldersJSON, _ := json.Marshal(oldVal)
		newFoldersJSON, _ := json.Marshal(trustedFolders)
		go analytics.SendConfigChangedAnalyticsEvent(conf, engine, logger, "trustedFolder", string(oldFoldersJSON), string(newFoldersJSON), types.FilePath(""), triggerSource, configResolver)
	}
}

func applyPathToEnv(conf configuration.Configuration, logger *zerolog.Logger, path string) {
	subLogger := logger.With().Str("method", "applyPathToEnv").Logger()
	conf.Set(configresolver.UserGlobalKey(types.SettingUserSettingsPath), path)

	if conf.GetBool(types.SettingIsLspInitialized) || !types.IsDefaultEnvReady(conf) {
		return
	}

	cachedPath := conf.GetString(types.SettingCachedOriginalPath)
	var newPath string
	if len(path) > 0 {
		_ = os.Unsetenv("Path")
		subLogger.Debug().Msg("adding configured path to PATH")
		newPath = path + string(os.PathListSeparator) + cachedPath
	} else {
		subLogger.Debug().Msg("restoring initial path")
		newPath = cachedPath
	}

	err := os.Setenv("PATH", newPath)
	if err != nil {
		subLogger.Err(err).Msgf("couldn't add path %s", path)
	}
	subLogger.Debug().Msgf("new PATH is '%s'", os.Getenv("PATH"))
}

func applySnykLearnCodeActions(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
	v, ok := settingBool(settings, types.SettingEnableSnykLearnCodeActions)
	if !ok {
		return
	}
	key := configresolver.UserGlobalKey(types.SettingEnableSnykLearnCodeActions)
	oldValue := conf.GetBool(key)
	conf.Set(key, v)
	if oldValue != v && conf.GetBool(types.SettingIsLspInitialized) {
		analytics.SendConfigChangedAnalytics(conf, engine, logger, configEnableSnykLearnCodeActions, oldValue, v, triggerSource, configResolver)
	}
}

func applySnykOssQuickFixCodeActions(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
	v, ok := settingBool(settings, types.SettingEnableSnykOssQuickFixActions)
	if !ok {
		return
	}
	key := configresolver.UserGlobalKey(types.SettingEnableSnykOssQuickFixActions)
	oldValue := conf.GetBool(key)
	conf.Set(key, v)
	if oldValue != v && conf.GetBool(types.SettingIsLspInitialized) {
		analytics.SendConfigChangedAnalytics(conf, engine, logger, configEnableSnykOSSQuickFixCodeActions, oldValue, v, triggerSource, configResolver)
	}
}

func applySnykOpenBrowserActions(conf configuration.Configuration, settings map[string]*types.ConfigSetting) {
	if v, ok := settingBool(settings, types.SettingEnableSnykOpenBrowserActions); ok {
		conf.Set(configresolver.UserGlobalKey(types.SettingEnableSnykOpenBrowserActions), v)
	}
}

func applyMcpConfiguration(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
	n := di.Notifier()
	if v, ok := settingBool(settings, types.SettingAutoConfigureMcpServer); ok {
		key := configresolver.UserGlobalKey(types.SettingAutoConfigureMcpServer)
		oldValue := conf.GetBool(key)
		conf.Set(key, v)
		if oldValue != v {
			if conf.GetBool(types.SettingIsLspInitialized) {
				go analytics.SendConfigChangedAnalytics(conf, engine, logger, configAutoConfigureSnykMcpServer, oldValue, v, triggerSource, configResolver)
			}
			mcpWorkflow.CallMcpConfigWorkflow(conf, di.ConfigResolver(), engine, logger, n, true, false)
		}
	}

	if v, ok := settingStr(settings, types.SettingSecureAtInceptionExecutionFreq); ok {
		key := configresolver.UserGlobalKey(types.SettingSecureAtInceptionExecutionFreq)
		oldValue := conf.GetString(key)
		conf.Set(key, v)
		if oldValue != v {
			if conf.GetBool(types.SettingIsLspInitialized) {
				go analytics.SendConfigChangedAnalytics(conf, engine, logger, configSecureAtInceptionExecutionFrequency, oldValue, v, triggerSource, configResolver)
			}
			mcpWorkflow.CallMcpConfigWorkflow(conf, di.ConfigResolver(), engine, logger, n, false, true)
		}
	}
}

func applyProxyConfig(conf configuration.Configuration, settings map[string]*types.ConfigSetting) {
	if v, ok := settingStr(settings, types.SettingProxyHttp); ok && v != "" {
		conf.Set(configresolver.UserGlobalKey(types.SettingProxyHttp), v)
	}
	if v, ok := settingStr(settings, types.SettingProxyHttps); ok && v != "" {
		conf.Set(configresolver.UserGlobalKey(types.SettingProxyHttps), v)
	}
	if v, ok := settingStr(settings, types.SettingProxyNoProxy); ok && v != "" {
		conf.Set(configresolver.UserGlobalKey(types.SettingProxyNoProxy), v)
	}
}

func applyEnvironment(conf configuration.Configuration, logger *zerolog.Logger, settings map[string]*types.ConfigSetting) {
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
			logger.Err(err).Msgf("couldn't set env variable %s", envVar)
		}
	}
}

func applyCodeEndpoint(conf configuration.Configuration, settings map[string]*types.ConfigSetting) {
	if v, ok := settingStr(settings, types.SettingCodeEndpoint); ok && v != "" {
		conf.Set(configresolver.UserGlobalKey(types.SettingCodeEndpoint), strings.TrimSpace(v))
	}
}

func applyPublishSecurityAtInceptionRules(conf configuration.Configuration, settings map[string]*types.ConfigSetting) {
	if v, ok := settingBool(settings, types.SettingPublishSecurityAtInceptionRules); ok {
		conf.Set(configresolver.UserGlobalKey(types.SettingPublishSecurityAtInceptionRules), v)
	}
}

func applyCliReleaseChannel(conf configuration.Configuration, settings map[string]*types.ConfigSetting) {
	if v, ok := settingStr(settings, types.SettingCliReleaseChannel); ok && v != "" {
		conf.Set(configresolver.UserGlobalKey(types.SettingCliReleaseChannel), strings.TrimSpace(v))
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
// It loads the existing FolderConfig (unenriched), applies the LspFolderConfig updates, and returns
// the processed config without persisting. The caller is responsible for batch-persisting all changes.
// Returns: (processedConfig, oldSnapshot, newSnapshot, configChanged)
func processSingleLspFolderConfig(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, path types.FilePath, incomingMap map[types.FilePath]types.LspFolderConfig, notifier notification.Notifier) (types.FolderConfig, types.FolderConfigSnapshot, types.FolderConfigSnapshot, bool) {
	subLogger := logger.With().Str("method", "processSingleLspFolderConfig").Str("path", string(path)).Logger()
	resolver := di.ConfigResolver()
	fc := config.GetUnenrichedFolderConfigFromEngine(engine, resolver, path, logger)

	// Capture old snapshot BEFORE applying updates
	oldSnapshot := types.ReadFolderConfigSnapshot(conf, types.PathKey(path))

	// Validate that the changes are allowed, then apply the new config.
	normalizedPath := fc.FolderPath
	applyChanged := false
	if incoming, hasIncoming := incomingMap[normalizedPath]; hasIncoming {
		hasLockedFieldRejections := validateLockedFields(conf, fc, &incoming, &subLogger)
		if hasLockedFieldRejections {
			folderName := filepath.Base(string(fc.FolderPath))
			notifier.SendShowMessage(sglsp.MTWarning,
				fmt.Sprintf("Failed to update %s: Some settings are locked by your organization's policy", folderName))
		}

		applyChanged = fc.ApplyLspUpdate(&incoming)
	}

	updateFolderOrgIfNeeded(conf, engine, logger, fc, fc, oldSnapshot, notifier)
	di.FeatureFlagService().PopulateFolderConfig(fc)

	newSnapshot := types.ReadFolderConfigSnapshot(conf, normalizedPath)
	configChanged := applyChanged

	return *fc, oldSnapshot, newSnapshot, configChanged
}

// validateLockedFields checks if any fields in the incoming LspFolderConfig are locked by LDX-Sync.
// Returns true if any fields were rejected due to being locked.
// If the incoming update changes PreferredOrg, locks are evaluated against the NEW org's policies
// to prevent bypassing stricter locks during an org switch.
func validateLockedFields(conf configuration.Configuration, folderConfig *types.FolderConfig, incoming *types.LspFolderConfig, subLogger *zerolog.Logger) bool {
	resolver := di.ConfigResolver()
	if resolver == nil || incoming.Settings == nil {
		return false
	}

	restoreOldOrg := temporarilyApplyNewOrgForValidation(conf, folderConfig, incoming)
	defer func() {
		if restoreOldOrg != nil {
			restoreOldOrg()
		}
	}()

	updatesRejected := false
	for settingName, cs := range incoming.Settings {
		if cs == nil || !cs.Changed {
			continue
		}
		if !types.IsFolderScopedSetting(resolver.ConfigurationOptionsMetaData(), settingName) {
			continue
		}
		if resolver.IsLocked(settingName, folderConfig) {
			subLogger.Info().
				Str("setting", settingName).
				Msg("Rejecting change to locked setting - locked by organization policy")
			updatesRejected = true
			delete(incoming.Settings, settingName)
		}
	}

	return updatesRejected
}

// temporarilyApplyNewOrgForValidation sets the new org in conf so ConfigResolver
// evaluates locks against the target org during an org switch. Returns a restore
// function that must be called to undo the temporary mutation.
func temporarilyApplyNewOrgForValidation(conf configuration.Configuration, folderConfig *types.FolderConfig, incoming *types.LspFolderConfig) func() {
	preferredOrg, ok := incoming.Settings[types.SettingPreferredOrg]
	if !ok || preferredOrg == nil || preferredOrg.Value == nil {
		return nil
	}
	newOrg, ok := preferredOrg.Value.(string)
	if !ok || newOrg == folderConfig.PreferredOrg() {
		return nil
	}
	folderPath := string(types.PathKey(folderConfig.GetFolderPath()))
	if folderPath == "" {
		return nil
	}

	orgKey := configresolver.UserFolderKey(folderPath, types.SettingOrgSetByUser)
	prefKey := configresolver.UserFolderKey(folderPath, types.SettingPreferredOrg)
	oldOrgVal := conf.Get(orgKey)
	oldPrefVal := conf.Get(prefKey)

	conf.Set(orgKey, &configresolver.LocalConfigField{Value: true, Changed: true})
	conf.Set(prefKey, &configresolver.LocalConfigField{Value: newOrg, Changed: true})

	return func() {
		if oldOrgVal != nil {
			conf.Set(orgKey, oldOrgVal)
		} else {
			conf.Unset(orgKey)
		}
		if oldPrefVal != nil {
			conf.Set(prefKey, oldPrefVal)
		} else {
			conf.Unset(prefKey)
		}
	}
}

func updateFolderOrgIfNeeded(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, fc *types.FolderConfig, folderConfig *types.FolderConfig, oldSnapshot types.FolderConfigSnapshot, notifier notification.Notifier) {
	orgSettingsChanged := fc != nil && !folderConfigsOrgSettingsEqual(oldSnapshot, *folderConfig)

	if orgSettingsChanged {
		updateFolderConfigOrg(conf, logger, folderConfig, oldSnapshot)
		ws := config.GetWorkspace(conf)
		folder := ws.GetFolderContaining(folderConfig.FolderPath)
		if folder != nil {
			di.LdxSyncService().RefreshConfigFromLdxSync(context.Background(), conf, engine, logger, []types.Folder{folder}, notifier)
		}
		return
	}

	// No explicit org change from client; inherit global org for folders that have no org setup yet
	if oldSnapshot.PreferredOrg == "" && !oldSnapshot.OrgSetByUser && types.GetGlobalOrganization(conf) != "" {
		types.SetPreferredOrgAndOrgSetByUser(conf, types.PathKey(folderConfig.FolderPath), types.GetGlobalOrganization(conf), false)
	}
}

func handleFolderCacheClearing(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, path types.FilePath, oldSnapshot, newSnapshot types.FolderConfigSnapshot, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
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

		ws := config.GetWorkspace(conf)
		if ws != nil {
			ws.GetScanSnapshotClearerExister().ClearFolder(path)
		}
	}

	sendFolderConfigAnalytics(conf, engine, logger, path, triggerSource, oldSnapshot, newSnapshot, configResolver)
}

func sendFolderConfigUpdateIfNeeded(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, notifier notification.Notifier, folderConfigs []types.FolderConfig, needsToSendUpdate bool, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
	// Don't send folder configs on initialize, since initialized will always send them.
	if needsToSendUpdate && triggerSource != analytics.TriggerSourceInitialize {
		lspConfig := command.BuildLspConfiguration(conf, engine, logger, nil, di.ConfigResolver())
		notifier.Send(lspConfig)
	}
}

func sendFolderConfigAnalytics(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, path types.FilePath, triggerSource analytics.TriggerSource, oldSnapshot, newSnapshot types.FolderConfigSnapshot, configResolver types.ConfigResolverInterface) {
	// BaseBranch change
	if oldSnapshot.BaseBranch != newSnapshot.BaseBranch {
		go analytics.SendConfigChangedAnalyticsEvent(conf, engine, logger, configBaseBranch, oldSnapshot.BaseBranch, newSnapshot.BaseBranch, path, triggerSource, configResolver)
	}

	// AdditionalParameters change
	if !util.SlicesEqualIgnoringOrder(oldSnapshot.AdditionalParameters, newSnapshot.AdditionalParameters) {
		oldParamsJSON, _ := json.Marshal(oldSnapshot.AdditionalParameters)
		newParamsJSON, _ := json.Marshal(newSnapshot.AdditionalParameters)
		go analytics.SendConfigChangedAnalyticsEvent(conf, engine, logger, configAdditionalParameters, string(oldParamsJSON), string(newParamsJSON), path, triggerSource, configResolver)
	}

	// ReferenceFolderPath change
	if oldSnapshot.ReferenceFolderPath != newSnapshot.ReferenceFolderPath {
		go analytics.SendConfigChangedAnalyticsEvent(conf, engine, logger, configReferenceFolderPath, oldSnapshot.ReferenceFolderPath, newSnapshot.ReferenceFolderPath, path, triggerSource, configResolver)
	}

	// ScanCommandConfig change
	if !reflect.DeepEqual(oldSnapshot.ScanCommandConfig, newSnapshot.ScanCommandConfig) {
		oldConfigJSON, _ := json.Marshal(oldSnapshot.ScanCommandConfig)
		newConfigJSON, _ := json.Marshal(newSnapshot.ScanCommandConfig)
		go analytics.SendConfigChangedAnalyticsEvent(conf, engine, logger, configScanCommandConfig, string(oldConfigJSON), string(newConfigJSON), path, triggerSource, configResolver)
	}

	// PreferredOrg change
	if oldSnapshot.PreferredOrg != newSnapshot.PreferredOrg && newSnapshot.PreferredOrg != "" {
		go analytics.SendConfigChangedAnalyticsEvent(conf, engine, logger, configPreferredOrg, oldSnapshot.PreferredOrg, newSnapshot.PreferredOrg, path, triggerSource, configResolver)
	}

	// OrgSetByUser change
	if oldSnapshot.OrgSetByUser != newSnapshot.OrgSetByUser {
		go analytics.SendConfigChangedAnalyticsEvent(conf, engine, logger, configOrgSetByUser, oldSnapshot.OrgSetByUser, newSnapshot.OrgSetByUser, path, triggerSource, configResolver)
	}
}

// folderConfigsOrgSettingsEqual compares the pre-update snapshot with the current configuration state for the folder.
// Uses oldSnapshot (captured before ApplyLspUpdate) because after ApplyLspUpdate both folderConfig and fc
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

func updateFolderConfigOrg(conf configuration.Configuration, logger *zerolog.Logger, folderConfig *types.FolderConfig, oldSnapshot types.FolderConfigSnapshot) {
	currentSnap := types.ReadFolderConfigSnapshot(conf, folderConfig.FolderPath)

	// Ensure AutoDeterminedOrg is propagated from the old snapshot when not yet set.
	// (LDX-Sync writes it to FolderMetadataKey directly; this handles the case where it was set previously
	//  but hasn't been written to the new folderConfig's path yet.)
	if currentSnap.AutoDeterminedOrg == "" && oldSnapshot.AutoDeterminedOrg != "" {
		types.SetAutoDeterminedOrg(conf, folderConfig.FolderPath, oldSnapshot.AutoDeterminedOrg)
	}

	orgSetByUserJustChanged := currentSnap.OrgSetByUser != oldSnapshot.OrgSetByUser
	orgHasJustChanged := currentSnap.PreferredOrg != oldSnapshot.PreferredOrg
	if orgSetByUserJustChanged {
		if !currentSnap.OrgSetByUser {
			types.SetPreferredOrgAndOrgSetByUser(conf, folderConfig.FolderPath, "", false)
		}
	} else if orgHasJustChanged {
		inheritedFromGlobal := oldSnapshot.PreferredOrg == "" && currentSnap.PreferredOrg != "" && !currentSnap.OrgSetByUser
		if !inheritedFromGlobal {
			types.SetPreferredOrgAndOrgSetByUser(conf, folderConfig.FolderPath, currentSnap.PreferredOrg, true)
		}
	} else if !currentSnap.OrgSetByUser {
		types.SetPreferredOrgAndOrgSetByUser(conf, folderConfig.FolderPath, "", false)
	}
}

func sendDiagnosticsForNewSettings(conf configuration.Configuration, logger *zerolog.Logger) {
	ws := config.GetWorkspace(conf)
	if ws == nil {
		return
	}
	go ws.HandleConfigChange()
}
