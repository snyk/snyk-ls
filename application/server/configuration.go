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
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
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
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/infrastructure/analytics"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
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
			return handlePushModel(ctx, conf, engine, logger, params.Settings)
		}

		return handlePullModel(ctx, conf, engine, logger, srv)
	})
}

func handlePushModel(ctx context.Context, conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, params types.LspConfigurationParam) (bool, error) {
	triggerSource := analytics.TriggerSourceIDE
	if !conf.GetBool(types.SettingIsLspInitialized) {
		triggerSource = analytics.TriggerSourceInitialize
	}
	configResolver, ok := ctx2.ConfigResolverFromContext(ctx)
	if !ok {
		return false, errors.New("config resolver missing from context")
	}
	UpdateSettings(ctx, conf, engine, logger, params.Settings, params.FolderConfigs, triggerSource, configResolver)
	return true, nil
}

func handlePullModel(ctx context.Context, conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, srv *jrpc2.Server) (bool, error) {
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
	configResolver, ok := ctx2.ConfigResolverFromContext(ctx)
	if !ok {
		return false, errors.New("config resolver missing from context")
	}
	UpdateSettings(ctx, conf, engine, logger, fetched.Settings.Settings, fetched.Settings.FolderConfigs, triggerSource, configResolver)
	return true, nil
}

// processInitMetadata handles init-only metadata fields from InitializationOptions.
func processInitMetadata(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, opts types.InitializationOptions) {
	types.SetGlobalSystemDefault(conf, types.SettingClientProtocolVersion, opts.RequiredProtocolVersion) // TODO must be internal

	if opts.DeviceId != "" {
		types.SetGlobalSystemDefault(conf, types.SettingDeviceId, strings.TrimSpace(opts.DeviceId))
	}
	types.SetGlobalSystemDefault(conf, types.SettingOsArch, opts.OsArch)
	types.SetGlobalSystemDefault(conf, types.SettingOsPlatform, opts.OsPlatform)
	types.SetGlobalSystemDefault(conf, types.SettingRuntimeVersion, opts.RuntimeVersion)
	types.SetGlobalSystemDefault(conf, types.SettingRuntimeName, opts.RuntimeName)

	if opts.HoverVerbosity != nil {
		types.SetGlobalSystemDefault(conf, types.SettingHoverVerbosity, *opts.HoverVerbosity)
	}
	if opts.OutputFormat != nil {
		types.SetGlobalSystemDefault(conf, types.SettingFormat, *opts.OutputFormat)
	}

	autoAuth := true
	if v, ok := settingBool(opts.Settings, types.SettingAutomaticAuthentication); ok {
		autoAuth = v
	}
	types.SetGlobalSystemDefault(conf, types.SettingAutomaticAuthentication, autoAuth)

	applyPathToEnv(conf, logger, opts.Path)

	// SettingScanAutomatic is folder-scoped per register_configurations.go but
	// historically written here at UserGlobalKey; the helper marks the debt.
	autoScan := true
	if v, ok := settingStr(opts.Settings, types.SettingScanAutomatic); ok && v == "manual" {
		autoScan = false
	} else if b, bOk := settingBool(opts.Settings, types.SettingScanAutomatic); bOk {
		autoScan = b
	}
	types.SetGlobalDeferredFolderScope(conf, types.SettingScanAutomatic, autoScan)
}

// InitializeSettings processes settings from the LSP initialize request.
// Only settings explicitly marked Changed by the IDE are applied; IDE defaults
// (Changed=false) are left alone so they don't override ldx-sync or GAF defaults.
func InitializeSettings(ctx context.Context, conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, opts types.InitializationOptions) error {
	resolver, ok := ctx2.ConfigResolverFromContext(ctx)
	if !ok {
		return errors.New("config resolver missing from context")
	}

	processInitMetadata(conf, engine, logger, opts)
	// global
	globalOrgChanged, lockedMachineFields := processConfigSettings(ctx, conf, engine, logger, opts.Settings, analytics.TriggerSourceInitialize, resolver)
	// folder
	lockedFolderFields := processFolderConfigs(ctx, conf, engine, logger, opts.FolderConfigs, analytics.TriggerSourceInitialize, resolver, globalOrgChanged)

	var fm workflow.ConfigurationOptionsMetaData
	if resolver != nil {
		fm = resolver.ConfigurationOptionsMetaData()
	}
	notifyLockedFieldsRejected(mustNotifierFromContext(ctx), fm, lockedMachineFields, lockedFolderFields)
	return nil
}

// UpdateSettings processes settings from workspace/didChangeConfiguration.
func UpdateSettings(ctx context.Context, conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, folderConfigs []types.LspFolderConfig, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
	ws := config.GetWorkspace(conf)
	oldToken := config.GetToken(conf)

	previousState := make(map[types.FilePath]map[product.FilterableIssueType]bool)
	if ws != nil {
		for _, folder := range ws.Folders() {
			previousState[folder.Path()] = folder.DisplayableIssueTypes()
		}
	}

	globalOrgChanged, lockedMachineFields := processConfigSettings(ctx, conf, engine, logger, settings, triggerSource, configResolver)

	// Flush stale cached errors (e.g. 401s from a previous token) before
	// PopulateFolderConfig runs inside processFolderConfigs. Flushing here
	// ensures every folder sees fresh results with the new token.
	if newToken := config.GetToken(conf); newToken != "" && newToken != oldToken {
		mustFeatureFlagServiceFromContext(ctx).FlushCache()
	}

	lockedFolderFields := processFolderConfigs(ctx, conf, engine, logger, folderConfigs, triggerSource, configResolver, globalOrgChanged)

	var fm workflow.ConfigurationOptionsMetaData
	if configResolver != nil {
		fm = configResolver.ConfigurationOptionsMetaData()
	}
	n := mustNotifierFromContext(ctx)
	notifyLockedFieldsRejected(n, fm, lockedMachineFields, lockedFolderFields)

	if conf.GetBool(types.SettingIsLspInitialized) {
		lspConfig := command.BuildLspConfiguration(conf, engine, logger, nil, configResolver)
		n.Send(lspConfig)
	}

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

	refreshLdxSyncOnTokenChange(ctx, conf, engine, logger, ws, oldToken, n)
}

// refreshLdxSyncOnTokenChange triggers an LDX-Sync refresh when the token changes.
// ldxSyncService is read from ctx via mustLdxSyncServiceFromContext; notifier is passed by the caller.
func refreshLdxSyncOnTokenChange(ctx context.Context, conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, ws types.Workspace, oldToken string, notifier notification.Notifier) {
	newToken := config.GetToken(conf)
	if newToken == oldToken || newToken == "" {
		return
	}
	if ws == nil {
		return
	}
	folders := ws.Folders()
	if len(folders) == 0 {
		return
	}
	logger.Info().Msg("token changed via settings, refreshing LDX-Sync configuration")
	mustLdxSyncServiceFromContext(ctx).RefreshConfigFromLdxSync(context.Background(), conf, engine, logger, folders, notifier)
}

// validateLockedMachineFields rejects user PATCH attempts for machine-scope settings
// that are currently locked by an admin (LDX-Sync remote lock; see GetGlobalBool docs
// for phase numbering — locked-remote is phase 1 and always wins regardless of PATCH).
//
// MDM/locked-remote writes themselves are not blocked here: the lock arrives via
// LDX-Sync sync into RemoteMachineKey, which this function never inspects or
// touches. The IsFolderScopedSetting guard keeps the loop machine-only.
//
// Without rejection, locked PATCHes are silently shadowed by phase 1 but persist as
// ghost entries at UserGlobalKey — load-bearing if the admin later lifts the lock.
//
// Returns the names of rejected settings so the caller can fold them into a single
// deduplicated notification for the triggering event (see [IDE-1970]).
func validateLockedMachineFields(settings map[string]*types.ConfigSetting, configResolver types.ConfigResolverInterface, fm workflow.ConfigurationOptionsMetaData, subLogger *zerolog.Logger) []string {
	if configResolver == nil || len(settings) == 0 {
		return nil
	}
	var locked []string
	for name, cs := range settings {
		if cs == nil || !cs.Changed {
			continue
		}
		if types.IsFolderScopedSetting(fm, name) {
			continue
		}
		if !configResolver.IsLockedMachine(name) {
			continue
		}
		subLogger.Info().
			Str("setting", name).
			Msg("Rejecting machine-scope change to locked setting - locked by organization policy")
		delete(settings, name)
		locked = append(locked, name)
	}
	return locked
}

// notifyLockedFieldsRejected emits at most one notification for the triggering
// event (LSP initialize / didChangeConfiguration), summarizing every locked
// field that was rejected across machine-scope and folder-scope updates. Field
// names are deduplicated so that a setting locked in multiple folders only
// appears once, and each name is rendered with its registered display name
// (e.g. "Snyk Code Enabled") rather than the internal snake_case identifier.
// See [IDE-1970].
func notifyLockedFieldsRejected(notifier notification.Notifier, fm workflow.ConfigurationOptionsMetaData, lockedFieldGroups ...[]string) {
	// Dedup on the resolved display name rather than the raw identifier so two
	// distinct raw keys that resolve to the same display name (e.g. legacy and
	// canonical identifiers for the same setting) collapse to a single entry
	// in the user-facing message. Raw-name dedup is still handled because
	// displayNameFor falls back to the raw identifier when no annotation is
	// registered.
	seenDisplay := make(map[string]struct{})
	var displayNames []string
	for _, group := range lockedFieldGroups {
		for _, name := range group {
			dn := displayNameFor(fm, name)
			if _, ok := seenDisplay[dn]; ok {
				continue
			}
			seenDisplay[dn] = struct{}{}
			displayNames = append(displayNames, dn)
		}
	}
	if len(displayNames) == 0 {
		return
	}
	// Sort the display names so the notification is deterministic regardless of
	// map iteration order upstream; otherwise the same triggering event could
	// surface fields in different orders across runs, which would confuse users
	// and test fixtures.
	sort.Strings(displayNames)
	notifier.SendShowMessage(sglsp.MTWarning,
		fmt.Sprintf("Failed to update some settings: locked by your organization's policy (%s)",
			strings.Join(displayNames, ", ")))
}

// displayNameFor resolves a setting's user-facing display name from its
// registered config.displayName annotation, falling back to the raw setting
// identifier when no metadata is available (e.g. in tests that don't register
// flags, or for settings without a display-name annotation).
func displayNameFor(fm workflow.ConfigurationOptionsMetaData, name string) string {
	if fm == nil {
		return name
	}
	if dn, ok := fm.GetConfigurationOptionAnnotation(name, configresolver.AnnotationDisplayName); ok && dn != "" {
		return dn
	}
	return name
}

// processConfigSettings writes incoming settings to configuration and applies side effects.
// This replaces the old writeSettings + update* functions.
// Returns globalOrgChanged so the caller (processFolderConfigs) can fold the
// global reset into the single resetSummaryPanelForOrgChange call that covers
// per-folder org changes, plus the names of any machine-scope settings rejected
// for being locked. The caller is responsible for emitting a single
// deduplicated locked-fields notification for the triggering event (see
// [IDE-1970]).
func processConfigSettings(ctx context.Context, conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) (bool, []string) {
	conf.ClearCache()

	if len(settings) == 0 {
		return false, nil
	}

	subLogger := logger.With().Str("method", "processConfigSettings").Logger()
	var fm workflow.ConfigurationOptionsMetaData
	if configResolver != nil {
		fm = configResolver.ConfigurationOptionsMetaData()
	}
	lockedMachineFields := validateLockedMachineFields(settings, configResolver, fm, &subLogger)

	// Global "Project Defaults" reset: honor {changed:true, value:null} for the
	// org-scope global settings by Unsetting the user override so the resolver
	// falls back to LDX-Sync / flagset default. Runs BEFORE the typed appliers and
	// deletes handled keys from settings, so a reset never double-applies (the
	// typed appliers' read helpers skip a nil value anyway, but deleting keeps the
	// intent explicit and avoids spurious analytics).
	globalResetOrgChanged := applyGlobalResets(ctx, conf, engine, logger, settings, triggerSource, configResolver)

	authService := mustAuthenticationServiceFromContext(ctx)
	applyApiEndpoints(conf, engine, logger, settings, triggerSource, configResolver, authService)
	applyAuthenticationMethod(conf, engine, logger, settings, triggerSource, configResolver, authService)
	applyToken(settings, authService)
	applyAutomaticAuthentication(conf, settings)
	applyProductEnablement(conf, engine, logger, settings, triggerSource, configResolver)
	applySeverityFilter(conf, engine, logger, settings, triggerSource, configResolver)
	applyRiskScoreThreshold(conf, engine, logger, settings, triggerSource, configResolver)
	applyIssueViewOptions(conf, engine, logger, settings, triggerSource, configResolver)
	applyDeltaFindings(conf, engine, logger, settings, triggerSource, configResolver)
	applyAutoScan(conf, settings)
	globalOrgChanged := applyOrganization(ctx, conf, engine, logger, settings, triggerSource, configResolver) || globalResetOrgChanged
	applyCliConfig(conf, settings)
	applyUserSettingsPath(conf, settings)
	applyEnvironment(conf, logger, settings)
	applyCliBaseDownloadURL(conf, engine, logger, settings, triggerSource, configResolver)
	applyErrorReporting(conf, engine, logger, settings, triggerSource, configResolver)
	applyManageBinariesAutomatically(conf, engine, logger, settings, triggerSource, configResolver)
	applyTrustEnabledFromSettings(conf, engine, logger, settings, triggerSource, configResolver)
	applyTrustedFoldersFromSettings(conf, engine, logger, settings, triggerSource, configResolver)
	applySnykLearnCodeActions(conf, engine, logger, settings, triggerSource, configResolver)
	applySnykOssQuickFixCodeActions(conf, engine, logger, settings, triggerSource, configResolver)
	applySnykOpenBrowserActions(conf, settings)
	applyMcpConfiguration(mustNotifierFromContext(ctx), conf, engine, logger, settings, triggerSource, configResolver)
	applyPublishSecurityAtInceptionRules(conf, settings)
	// this is without function right now, we do not use/distribute proxy settings from/to IDEs
	applyProxyConfig(conf, settings)
	applyCodeEndpoint(conf, settings)
	applyCliReleaseChannel(conf, settings)

	return globalOrgChanged, lockedMachineFields
}

// hasFilterChangesInLspConfig detects if any filter settings are marked as Changed in the incoming LspFolderConfig.
// Filter settings include: severity filters, issue view options, and risk score threshold.
// Returns true if any filter-related setting has Changed=true.
func hasFilterChangesInLspConfig(lspConfig *types.LspFolderConfig) bool {
	if lspConfig == nil || lspConfig.Settings == nil {
		return false
	}

	filterSettings := map[string]bool{
		types.SettingSeverityFilterCritical: true,
		types.SettingSeverityFilterHigh:     true,
		types.SettingSeverityFilterMedium:   true,
		types.SettingSeverityFilterLow:      true,
		types.SettingIssueViewOpenIssues:    true,
		types.SettingIssueViewIgnoredIssues: true,
		types.SettingRiskScoreThreshold:     true,
	}

	for settingName, setting := range lspConfig.Settings {
		if filterSettings[settingName] && setting != nil && setting.Changed {
			return true
		}
	}

	return false
}

// processFolderConfigs handles the folder configuration portion of incoming settings.
// When globalOrgChanged is true, every workspace folder is treated as having an
// org change so the Summary Panel reset is folded into the single
// resetSummaryPanelForOrgChange call below (avoiding the double-flash that used
// to occur when applyOrganization reset separately from processFolderConfigs).
//
// Returns the union of all folder-scope setting names rejected for being locked
// across every processed folder. The caller is responsible for folding this
// list (together with machine-scope rejections) into a single deduplicated
// locked-fields notification per triggering event — see [IDE-1970].
func processFolderConfigs(ctx context.Context, conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, folderConfigs []types.LspFolderConfig, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface, globalOrgChanged bool) []string {
	notifier := mustNotifierFromContext(ctx)
	incomingMap := buildIncomingLspConfigMap(folderConfigs)
	allPaths := gatherAllFolderPathsFromLspConfigs(incomingMap, config.GetWorkspace(conf))

	logger.Debug().
		Int("incomingFolderConfigCount", len(folderConfigs)).
		Int("incomingMapCount", len(incomingMap)).
		Int("allPathsCount", len(allPaths)).
		Bool("globalOrgChanged", globalOrgChanged).
		Msg("processFolderConfigs - processing folder configs")

	var processedConfigs []types.FolderConfig
	var changedConfigs []*types.FolderConfig
	var lockedFields []string
	filterChanged := false
	orgChangedFolderPaths := make(map[types.FilePath]struct{})

	// If the global org changed, every workspace folder needs a Summary Panel
	// reset so we seed the set up front. Per-folder org changes (e.g. PreferredOrg
	// via folderConfigs) get unioned in below.
	if globalOrgChanged {
		for _, p := range workspaceFolderPaths(conf) {
			orgChangedFolderPaths[p] = struct{}{}
		}
	}

	for path := range allPaths {
		result := processSingleLspFolderConfig(ctx, conf, engine, logger, path, incomingMap, notifier, configResolver)
		if result.orgSettingsChanged {
			orgChangedFolderPaths[path] = struct{}{}
		}

		if result.configChanged {
			cfg := result.config
			changedConfigs = append(changedConfigs, &cfg)
		}

		lockedFields = append(lockedFields, result.lockedFields...)

		// Check for filter changes INDEPENDENTLY of configChanged
		// Filter changes are folder-scope settings, so we need to detect them separately
		if incomingLspConfig, hasIncoming := incomingMap[path]; hasIncoming {
			if hasFilterChangesInLspConfig(&incomingLspConfig) {
				filterChanged = true
			}
		}

		handleFolderCacheClearing(conf, engine, logger, path, result.oldSnapshot, result.newSnapshot, triggerSource, configResolver)
		processedConfigs = append(processedConfigs, result.config)
	}

	if len(changedConfigs) > 0 {
		if err := folderconfig.BatchUpdateFolderConfigs(conf, changedConfigs, logger); err != nil {
			logger.Err(err).Int("count", len(changedConfigs)).Msg("failed to batch update folder configs")
		}
	}

	// Trigger diagnostics republishing if filter changes detected
	if filterChanged && conf.GetBool(types.SettingIsLspInitialized) {
		sendDiagnosticsForNewSettings(conf, logger)
	}

	if conf.GetBool(types.SettingIsLspInitialized) && len(orgChangedFolderPaths) > 0 {
		paths := make([]types.FilePath, 0, len(orgChangedFolderPaths))
		for p := range orgChangedFolderPaths {
			paths = append(paths, p)
		}
		resetSummaryPanelForOrgChange(mustScanStateAggregatorFromContext(ctx), paths)
	}

	sendFolderConfigUpdateIfNeeded(conf, engine, logger, notifier, processedConfigs, len(changedConfigs) > 0, triggerSource, configResolver)

	return lockedFields
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

func settingStringSlice(settings map[string]*types.ConfigSetting, name string) ([]string, bool) {
	s, ok := settings[name]
	if !ok || s == nil || !s.Changed {
		return nil, false
	}
	if ss, ok := s.Value.([]string); ok {
		return ss, true
	}
	// JSON unmarshals arrays as []interface{}
	if arr, ok := s.Value.([]interface{}); ok {
		result := make([]string, 0, len(arr))
		for _, v := range arr {
			if str, ok := v.(string); ok {
				result = append(result, str)
			}
		}
		return result, true
	}
	return nil, false
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

func applyApiEndpoints(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface, authService authentication.AuthenticationService) {
	v, ok := settingStr(settings, types.SettingApiEndpoint)
	if !ok {
		return
	}
	snykApiUrl := strings.TrimSpace(v)
	oldEndpoint := types.GetGlobalString(conf, types.SettingApiEndpoint)
	endpointsUpdated := command.ApplyEndpointChange(context.Background(), conf, authService, logger, snykApiUrl)
	if endpointsUpdated && conf.GetBool(types.SettingIsLspInitialized) {
		analytics.SendConfigChangedAnalytics(conf, engine, logger, configEndpoint, oldEndpoint, snykApiUrl, triggerSource, configResolver)
	}
}

func applyToken(settings map[string]*types.ConfigSetting, authService authentication.AuthenticationService) {
	tokenFromIde, tokenExistsInMap := settings[types.SettingToken]
	if !tokenExistsInMap || tokenFromIde == nil {
		return
	}
	tokenAsString, parsable := tokenFromIde.Value.(string)
	if parsable && authService != nil {
		authService.UpdateCredentials(tokenAsString, false, false)
	}
}

func applyAuthenticationMethod(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface, authService authentication.AuthenticationService) {
	v, ok := settingStr(settings, types.SettingAuthenticationMethod)
	if !ok || types.AuthenticationMethod(v) == types.EmptyAuthenticationMethod {
		return
	}
	oldValue := config.GetAuthenticationMethodFromConfig(conf)
	command.ApplyAuthMethodChange(conf, authService, logger, types.AuthenticationMethod(v))
	if oldValue != types.AuthenticationMethod(v) && conf.GetBool(types.SettingIsLspInitialized) {
		analytics.SendConfigChangedAnalytics(conf, engine, logger, configAuthenticationMethod, oldValue, types.AuthenticationMethod(v), triggerSource, configResolver)
	}
}

func applyAutomaticAuthentication(conf configuration.Configuration, settings map[string]*types.ConfigSetting) {
	if v, ok := settingBool(settings, types.SettingAutomaticAuthentication); ok {
		types.SetGlobalUser(conf, types.SettingAutomaticAuthentication, v)
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

func applyProductEnablement(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
	lspInit := conf.GetBool(types.SettingIsLspInitialized)
	logIncomingProductSettings(logger, settings)
	if v, ok := settingBool(settings, types.SettingSnykCodeEnabled); ok {
		key := configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)
		oldValue := conf.GetBool(key)
		conf.Set(key, v)
		if oldValue != v {
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
			if lspInit {
				analytics.SendConfigChangedAnalytics(conf, engine, logger, configActivateSnykSecrets, oldValue, v, triggerSource, configResolver)
			}
		}
	}
}

func applySeverityFilter(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
	sf := extractSeverityFilterFromSettings(conf, settings)
	if sf == nil {
		return
	}

	oldValue := config.GetFilterSeverity(conf)
	modified := config.SetSeverityFilterOnConfig(conf, sf, logger)
	if !modified {
		return
	}
	if conf.GetBool(types.SettingIsLspInitialized) {
		sendDiagnosticsForNewSettings(conf, logger)
		analytics.SendAnalyticsForFields(conf, engine, logger, "filterSeverity", &oldValue, sf, triggerSource, map[string]func(*types.SeverityFilter) any{
			"Critical": func(s *types.SeverityFilter) any { return s.Critical },
			"High":     func(s *types.SeverityFilter) any { return s.High },
			"Medium":   func(s *types.SeverityFilter) any { return s.Medium },
			"Low":      func(s *types.SeverityFilter) any { return s.Low },
		}, configResolver)
	}
}

// extractSeverityFilterFromSettings builds a SeverityFilter from settings.
// Extracts severity filter from individual boolean keys (SettingSeverityFilterCritical, etc.).
func extractSeverityFilterFromSettings(conf configuration.Configuration, settings map[string]*types.ConfigSetting) *types.SeverityFilter {
	severityKeys := []string{
		types.SettingSeverityFilterCritical,
		types.SettingSeverityFilterHigh,
		types.SettingSeverityFilterMedium,
		types.SettingSeverityFilterLow,
	}
	hasSeverity := false
	for _, k := range severityKeys {
		if s, ok := settings[k]; ok && s != nil && s.Changed {
			hasSeverity = true
			break
		}
	}
	if !hasSeverity {
		return nil
	}
	sf := types.GetFilterSeverityFromConfig(conf)
	sf.Critical = settingBoolWithDefault(settings, types.SettingSeverityFilterCritical, sf.Critical)
	sf.High = settingBoolWithDefault(settings, types.SettingSeverityFilterHigh, sf.High)
	sf.Medium = settingBoolWithDefault(settings, types.SettingSeverityFilterMedium, sf.Medium)
	sf.Low = settingBoolWithDefault(settings, types.SettingSeverityFilterLow, sf.Low)
	return &sf
}

func settingBoolWithDefault(settings map[string]*types.ConfigSetting, key string, defaultVal bool) bool {
	if s, ok := settings[key]; ok && s != nil && s.Changed {
		if b, ok := s.Value.(bool); ok {
			return b
		}
	}
	return defaultVal
}

func applyRiskScoreThreshold(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
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
	if conf.GetBool(types.SettingIsLspInitialized) {
		sendDiagnosticsForNewSettings(conf, logger)
		analytics.SendConfigChangedAnalytics(conf, engine, logger, "riskScoreThreshold", oldValue, *riskScore, triggerSource, configResolver)
	}
}

func applyIssueViewOptions(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
	openPresent := settingPresent(settings, types.SettingIssueViewOpenIssues)
	ignoredPresent := settingPresent(settings, types.SettingIssueViewIgnoredIssues)
	if !openPresent && !ignoredPresent {
		return
	}

	ivo := config.GetIssueViewOptions(conf)
	if v, ok := settingBool(settings, types.SettingIssueViewOpenIssues); ok {
		ivo.OpenIssues = v
	}
	if v, ok := settingBool(settings, types.SettingIssueViewIgnoredIssues); ok {
		ivo.IgnoredIssues = v
	}

	oldValue := config.GetIssueViewOptions(conf)
	modified := config.SetIssueViewOptionsOnConfig(conf, &ivo, logger)
	if !modified {
		return
	}
	if conf.GetBool(types.SettingIsLspInitialized) {
		sendDiagnosticsForNewSettings(conf, logger)
		analytics.SendAnalyticsForFields(conf, engine, logger, "issueViewOptions", &oldValue, &ivo, triggerSource, map[string]func(*types.IssueViewOptions) any{
			"OpenIssues":    func(s *types.IssueViewOptions) any { return s.OpenIssues },
			"IgnoredIssues": func(s *types.IssueViewOptions) any { return s.IgnoredIssues },
		}, configResolver)
	}
}

func applyDeltaFindings(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
	v, ok := settingBool(settings, types.SettingScanNetNew)
	if !ok {
		return
	}
	oldValue := conf.GetBool(configresolver.UserGlobalKey(types.SettingScanNetNew))
	modified := oldValue != v
	types.SetGlobalDeferredFolderScope(conf, types.SettingScanNetNew, v)
	if !modified {
		return
	}
	if conf.GetBool(types.SettingIsLspInitialized) {
		sendDiagnosticsForNewSettings(conf, logger)
		analytics.SendConfigChangedAnalytics(conf, engine, logger, configEnableDeltaFindings, oldValue, v, triggerSource, configResolver)
	}
}

func applyAutoScan(conf configuration.Configuration, settings map[string]*types.ConfigSetting) {
	// Auto scan true by default unless explicitly disabled
	var autoScan bool
	if v, ok := settingStr(settings, types.SettingScanAutomatic); ok {
		autoScan = v != "manual"
	} else if b, bOk := settingBool(settings, types.SettingScanAutomatic); bOk {
		autoScan = b
	} else {
		return
	}
	types.SetGlobalDeferredFolderScope(conf, types.SettingScanAutomatic, autoScan)
}

// applyOrganization persists the global org change and emits analytics.
// Returns true when the global org actually changed and the LSP is initialized
// so the caller (processConfigSettings → processFolderConfigs) can union the
// affected workspace folders into the single resetSummaryPanelForOrgChange call.
// isReset reports whether an incoming ConfigSetting is a reset marker:
// {changed:true, value:null}. This is the global-scope analog of
// folder_config.go::isFolderReset.
func isReset(cs *types.ConfigSetting) bool {
	return cs != nil && cs.Changed && cs.Value == nil
}

// globalResetFilterKeys is the subset of GlobalResettableSettings whose reset
// must trigger a diagnostics refresh (severity filters, issue-view options, risk
// score threshold), mirroring applySeverityFilter / applyIssueViewOptions.
var globalResetFilterKeys = map[string]bool{
	types.SettingSeverityFilterCritical: true,
	types.SettingSeverityFilterHigh:     true,
	types.SettingSeverityFilterMedium:   true,
	types.SettingSeverityFilterLow:      true,
	types.SettingIssueViewOpenIssues:    true,
	types.SettingIssueViewIgnoredIssues: true,
	types.SettingRiskScoreThreshold:     true,
}

// applyGlobalResets clears user overrides for org-scope global ("Project Defaults")
// settings sent as {changed:true, value:null}. For each handled key it Unsets the
// user override (so the resolver falls back to LDX-Sync / flagset default) and
// deletes the entry from settings so the downstream typed appliers do not also act
// on it. organization is handled specially via config.ResetOrganization because it
// is not stored at UserGlobalKey. Returns true if the effective global org changed,
// so the caller can fold the summary-panel reset into the single org-change path.
//
// Locked fields: validateLockedMachineFields runs first and strips locked
// machine-scope entries (incl. a locked organization), so they never reach here.
// For locked folder-scope LDX-Sync values, the user override is still cleared but
// GetGlobal* phase-1 keeps the locked remote value winning — correct.
func applyGlobalResets(ctx context.Context, conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) bool {
	orgChanged := false
	filterReset := false
	for _, name := range types.GlobalResettableSettings {
		cs, ok := settings[name]
		if !ok || !isReset(cs) {
			continue
		}

		if name == types.SettingOrganization {
			oldOrgId := types.GetGlobalOrganization(conf)
			config.ResetOrganization(conf)
			newOrgId := types.GetGlobalOrganization(conf)
			if oldOrgId != newOrgId && conf.GetBool(types.SettingIsLspInitialized) {
				analytics.SendConfigChangedAnalytics(conf, engine, logger, configOrganization, oldOrgId, newOrgId, triggerSource, configResolver)
				refreshFoldersForGlobalOrgChange(ctx, conf, engine, logger, oldOrgId, newOrgId)
				orgChanged = true
			}
		} else if types.HasGlobalUserOverride(conf, name) {
			types.UnsetGlobalUser(conf, name)
			if globalResetFilterKeys[name] {
				filterReset = true
			}
		}

		// Remove the handled reset so the typed appliers below skip it.
		delete(settings, name)
	}

	if filterReset && conf.GetBool(types.SettingIsLspInitialized) {
		sendDiagnosticsForNewSettings(conf, logger)
	}

	return orgChanged
}

func applyOrganization(ctx context.Context, conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) bool {
	v, ok := settingStr(settings, types.SettingOrganization)
	if !ok {
		return false
	}
	newOrg := strings.TrimSpace(v)
	oldOrgId := types.GetGlobalOrganization(conf)
	config.SetOrganization(conf, newOrg)
	newOrgId := types.GetGlobalOrganization(conf)
	if oldOrgId == newOrgId || !conf.GetBool(types.SettingIsLspInitialized) {
		return false
	}
	analytics.SendConfigChangedAnalytics(conf, engine, logger, configOrganization, oldOrgId, newOrgId, triggerSource, configResolver)
	refreshFoldersForGlobalOrgChange(ctx, conf, engine, logger, oldOrgId, newOrgId)

	return true
}

// refreshFoldersForGlobalOrgChange triggers an LDX-Sync refresh for folders that
// depend on the global org fallback (OrgSetByUser && PreferredOrg==""). Shared by
// applyOrganization (org explicitly set) and applyGlobalResets (org reset to
// fallback) so both go through the same, scoped refresh — never a full-workspace
// rescan.
func refreshFoldersForGlobalOrgChange(ctx context.Context, conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, oldOrgId, newOrgId string) {
	ws := config.GetWorkspace(conf)
	if ws == nil {
		return
	}
	foldersNeedingRefresh := findFoldersUsingGlobalOrgFallback(conf, ws.Folders())
	if len(foldersNeedingRefresh) == 0 {
		return
	}
	logger.Info().
		Int("folderCount", len(foldersNeedingRefresh)).
		Str("oldOrg", oldOrgId).
		Str("newOrg", newOrgId).
		Msg("global org changed, refreshing LDX-Sync for folders using global org fallback")
	ldxSyncService := mustLdxSyncServiceFromContext(ctx)
	notifier := mustNotifierFromContext(ctx)
	ldxSyncService.RefreshConfigFromLdxSync(context.Background(), conf, engine, logger, foldersNeedingRefresh, notifier)
}

// findFoldersUsingGlobalOrgFallback identifies folders that use the global org fallback.
// A folder uses global org fallback if: OrgSetByUser=true AND PreferredOrg=""
func findFoldersUsingGlobalOrgFallback(conf configuration.Configuration, folders []types.Folder) []types.Folder {
	var result []types.Folder
	for _, folder := range folders {
		s := types.ReadFolderConfigSnapshot(conf, folder.Path())
		if s.OrgSetByUser && s.PreferredOrg == "" {
			result = append(result, folder)
		}
	}
	return result
}

// resetSummaryPanelForOrgChange clears scan state for the given folders so the
// Summary Panel returns to its initial "no scans yet" state. The aggregator's
// Init re-emits a fresh snapshot, which IDE clients render as the empty summary panel.
func resetSummaryPanelForOrgChange(scanAgg scanstates.Aggregator, folderPaths []types.FilePath) {
	if scanAgg == nil || len(folderPaths) == 0 {
		return
	}
	scanAgg.Init(folderPaths)
}

func workspaceFolderPaths(conf configuration.Configuration) []types.FilePath {
	ws := config.GetWorkspace(conf)
	if ws == nil {
		return nil
	}
	folders := ws.Folders()
	folderPaths := make([]types.FilePath, 0, len(folders))
	for _, f := range folders {
		folderPaths = append(folderPaths, f.Path())
	}
	return folderPaths
}

func applyCliConfig(conf configuration.Configuration, settings map[string]*types.ConfigSetting) {
	if v, ok := settingBool(settings, types.SettingProxyInsecure); ok {
		types.SetGlobalUser(conf, types.SettingProxyInsecure, v)
		conf.Set(configuration.INSECURE_HTTPS, v)
	}
	if v, ok := settingStr(settings, types.SettingAdditionalParameters); ok {
		types.SetGlobalDeferredFolderScope(conf, types.SettingCliAdditionalOssParameters, strings.Split(v, " "))
	}
	if v, ok := settingStr(settings, types.SettingCliPath); ok {
		types.SetGlobalUser(conf, types.SettingCliPath, strings.TrimSpace(v))
	}
}

func applyCliBaseDownloadURL(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
	v, ok := settingStr(settings, types.SettingBinaryBaseUrl)
	if !ok {
		return
	}
	newURL := strings.TrimSpace(v)
	oldURL := types.GetGlobalString(conf, types.SettingBinaryBaseUrl)
	types.SetGlobalUser(conf, types.SettingBinaryBaseUrl, newURL)
	if oldURL != newURL && conf.GetBool(types.SettingIsLspInitialized) {
		analytics.SendConfigChangedAnalytics(conf, engine, logger, configCliBaseDownloadURL, oldURL, newURL, triggerSource, configResolver)
	}
}

func applyErrorReporting(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
	v, ok := settingBool(settings, types.SettingSendErrorReports)
	if !ok {
		return
	}
	oldValue := types.GetGlobalBool(conf, types.SettingSendErrorReports)
	types.SetGlobalUser(conf, types.SettingSendErrorReports, v)
	if oldValue != v && conf.GetBool(types.SettingIsLspInitialized) {
		analytics.SendConfigChangedAnalytics(conf, engine, logger, configSendErrorReports, oldValue, v, triggerSource, configResolver)
	}
}

func applyManageBinariesAutomatically(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
	v, ok := settingBool(settings, types.SettingAutomaticDownload)
	if !ok {
		return
	}
	oldValue := types.GetGlobalBool(conf, types.SettingAutomaticDownload)
	types.SetGlobalUser(conf, types.SettingAutomaticDownload, v)
	if oldValue != v && conf.GetBool(types.SettingIsLspInitialized) {
		analytics.SendConfigChangedAnalytics(conf, engine, logger, configManageBinariesAutomatically, oldValue, v, triggerSource, configResolver)
	}
}

func applyTrustEnabledFromSettings(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
	if v, ok := settingBool(settings, types.SettingTrustEnabled); ok {
		oldValue := types.GetGlobalBool(conf, types.SettingTrustEnabled)
		types.SetGlobalUser(conf, types.SettingTrustEnabled, v)
		if oldValue != v && conf.GetBool(types.SettingIsLspInitialized) {
			analytics.SendConfigChangedAnalytics(conf, engine, logger, configEnableTrustedFoldersFeature, oldValue, v, triggerSource, configResolver)
		}
	}
}

func applyTrustedFoldersFromSettings(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
	if folders, ok := settingStringSlice(settings, types.SettingTrustedFolders); ok {
		applyTrustedFolders(conf, engine, logger, folders, triggerSource, configResolver)
	}
}

func applyTrustedFolders(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, folders []string, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
	if folders == nil {
		return
	}
	oldVal := types.GetGlobalSliceFilePath(conf, types.SettingTrustedFolders)
	var trustedFolders []types.FilePath
	for _, folder := range folders {
		trustedFolders = append(trustedFolders, types.FilePath(folder))
	}
	types.SetGlobalUser(conf, types.SettingTrustedFolders, trustedFolders)
	if !util.SlicesEqualIgnoringOrder(oldVal, trustedFolders) && conf.GetBool(types.SettingIsLspInitialized) {
		oldFoldersJSON, _ := json.Marshal(oldVal)
		newFoldersJSON, _ := json.Marshal(trustedFolders)
		go analytics.SendConfigChangedAnalyticsEvent(conf, engine, logger, "trustedFolder", string(oldFoldersJSON), string(newFoldersJSON), types.FilePath(""), triggerSource, configResolver)
	}
}

func applyPathToEnv(conf configuration.Configuration, logger *zerolog.Logger, path string) {
	subLogger := logger.With().Str("method", "applyPathToEnv").Logger()
	types.SetGlobalUser(conf, types.SettingUserSettingsPath, path)

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

func applyUserSettingsPath(conf configuration.Configuration, settings map[string]*types.ConfigSetting) {
	v, ok := settingStr(settings, types.SettingUserSettingsPath)
	if !ok {
		return
	}
	types.SetGlobalUser(conf, types.SettingUserSettingsPath, v)
}

func applySnykLearnCodeActions(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
	v, ok := settingBool(settings, types.SettingEnableSnykLearnCodeActions)
	if !ok {
		return
	}
	oldValue := types.GetGlobalBool(conf, types.SettingEnableSnykLearnCodeActions)
	types.SetGlobalUser(conf, types.SettingEnableSnykLearnCodeActions, v)
	if oldValue != v && conf.GetBool(types.SettingIsLspInitialized) {
		analytics.SendConfigChangedAnalytics(conf, engine, logger, configEnableSnykLearnCodeActions, oldValue, v, triggerSource, configResolver)
	}
}

func applySnykOssQuickFixCodeActions(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
	v, ok := settingBool(settings, types.SettingEnableSnykOssQuickFixActions)
	if !ok {
		return
	}
	oldValue := types.GetGlobalBool(conf, types.SettingEnableSnykOssQuickFixActions)
	types.SetGlobalUser(conf, types.SettingEnableSnykOssQuickFixActions, v)
	if oldValue != v && conf.GetBool(types.SettingIsLspInitialized) {
		analytics.SendConfigChangedAnalytics(conf, engine, logger, configEnableSnykOSSQuickFixCodeActions, oldValue, v, triggerSource, configResolver)
	}
}

func applySnykOpenBrowserActions(conf configuration.Configuration, settings map[string]*types.ConfigSetting) {
	if v, ok := settingBool(settings, types.SettingEnableSnykOpenBrowserActions); ok {
		types.SetGlobalUser(conf, types.SettingEnableSnykOpenBrowserActions, v)
	}
}

func applyMcpConfiguration(n notification.Notifier, conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, settings map[string]*types.ConfigSetting, triggerSource analytics.TriggerSource, configResolver types.ConfigResolverInterface) {
	if v, ok := settingBool(settings, types.SettingAutoConfigureMcpServer); ok {
		oldValue := types.GetGlobalBool(conf, types.SettingAutoConfigureMcpServer)
		types.SetGlobalUser(conf, types.SettingAutoConfigureMcpServer, v)
		if oldValue != v {
			if conf.GetBool(types.SettingIsLspInitialized) {
				go analytics.SendConfigChangedAnalytics(conf, engine, logger, configAutoConfigureSnykMcpServer, oldValue, v, triggerSource, configResolver)
			}
			mcpWorkflow.CallMcpConfigWorkflow(conf, configResolver, engine, logger, n, true, false)
		}
	}

	if v, ok := settingStr(settings, types.SettingSecureAtInceptionExecutionFreq); ok {
		oldValue := types.GetGlobalString(conf, types.SettingSecureAtInceptionExecutionFreq)
		types.SetGlobalUser(conf, types.SettingSecureAtInceptionExecutionFreq, v)
		if oldValue != v {
			if conf.GetBool(types.SettingIsLspInitialized) {
				go analytics.SendConfigChangedAnalytics(conf, engine, logger, configSecureAtInceptionExecutionFrequency, oldValue, v, triggerSource, configResolver)
			}
			mcpWorkflow.CallMcpConfigWorkflow(conf, configResolver, engine, logger, n, false, true)
		}
	}
}

func applyProxyConfig(conf configuration.Configuration, settings map[string]*types.ConfigSetting) {
	if v, ok := settingStr(settings, types.SettingProxyHttp); ok && v != "" {
		types.SetGlobalUser(conf, types.SettingProxyHttp, v)
	}
	if v, ok := settingStr(settings, types.SettingProxyHttps); ok && v != "" {
		types.SetGlobalUser(conf, types.SettingProxyHttps, v)
	}
	if v, ok := settingStr(settings, types.SettingProxyNoProxy); ok && v != "" {
		types.SetGlobalUser(conf, types.SettingProxyNoProxy, v)
	}
}

func applyEnvironment(conf configuration.Configuration, logger *zerolog.Logger, settings map[string]*types.ConfigSetting) {
	v, ok := settingStr(settings, types.SettingAdditionalEnvironment)
	if !ok {
		// Field absent or unchanged: leave both the process env and the persisted value alone.
		// An empty-but-changed value (user cleared the field) has ok==true and falls through,
		// so the clear path below runs.
		return
	}

	// Diff against the previously-persisted value so keys the user removed get unset from the
	// process env. os.Setenv is one-way; without this, a re-save that drops a key would leave it
	// live in os.Environ() and leak into every subsequent CLI subprocess (updateSDKs seeds the
	// scan env from the process environment).
	oldKeys := parseEnvKeys(types.GetGlobalString(conf, types.SettingAdditionalEnvironment))
	newKeys := make(map[string]bool)

	for _, envVar := range strings.Split(v, ";") {
		parts := strings.SplitN(envVar, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		newKeys[key] = true
		if err := os.Setenv(key, parts[1]); err != nil {
			logger.Err(err).Msgf("couldn't set env variable %s", envVar)
		}
	}

	// Unset keys that were applied previously but are absent from the new value.
	for key := range oldKeys {
		if !newKeys[key] {
			if err := os.Unsetenv(key); err != nil {
				logger.Err(err).Msgf("couldn't unset env variable %s", key)
			}
		}
	}

	// Persist the raw string so the settings dialog can repopulate this field on reopen.
	// On an empty value this writes "", clearing the persisted state so the field comes back blank.
	// os.Setenv alone is not readable back from config; SetGlobalUser writes to UserGlobalKey
	// which r.GetString(SettingAdditionalEnvironment, nil) resolves via the folder-scope chain.
	types.SetGlobalUser(conf, types.SettingAdditionalEnvironment, v)
}

// parseEnvKeys extracts the set of variable names from a "KEY=VAL;KEY2=VAL2" string.
// Malformed segments (no "=") are skipped, matching applyEnvironment's apply loop.
func parseEnvKeys(raw string) map[string]bool {
	keys := make(map[string]bool)
	if raw == "" {
		return keys
	}
	for _, envVar := range strings.Split(raw, ";") {
		parts := strings.SplitN(envVar, "=", 2)
		if len(parts) != 2 {
			continue
		}
		keys[parts[0]] = true
	}
	return keys
}

func applyCodeEndpoint(conf configuration.Configuration, settings map[string]*types.ConfigSetting) {
	if v, ok := settingStr(settings, types.SettingCodeEndpoint); ok && v != "" {
		types.SetGlobalUser(conf, types.SettingCodeEndpoint, strings.TrimSpace(v))
	}
}

func applyPublishSecurityAtInceptionRules(conf configuration.Configuration, settings map[string]*types.ConfigSetting) {
	if v, ok := settingBool(settings, types.SettingPublishSecurityAtInceptionRules); ok {
		types.SetGlobalUser(conf, types.SettingPublishSecurityAtInceptionRules, v)
	}
}

func applyCliReleaseChannel(conf configuration.Configuration, settings map[string]*types.ConfigSetting) {
	if v, ok := settingStr(settings, types.SettingCliReleaseChannel); ok && v != "" {
		types.SetGlobalUser(conf, types.SettingCliReleaseChannel, strings.TrimSpace(v))
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

// singleFolderResult is the structured return value of processSingleLspFolderConfig.
// Fields are exposed by name so callers don't have to positionally destructure a tuple.
type singleFolderResult struct {
	config             types.FolderConfig
	oldSnapshot        types.FolderConfigSnapshot
	newSnapshot        types.FolderConfigSnapshot
	configChanged      bool
	orgSettingsChanged bool
	lockedFields       []string
}

// processSingleLspFolderConfig processes an incoming LspFolderConfig from the IDE using PATCH semantics:
// - For pointer fields: nil = don't change, non-nil = set value
// - For *LocalConfigField: nil = don't change, Changed+Value = set, Changed+nil = reset
// It loads the existing FolderConfig (unenriched), applies the LspFolderConfig updates, and returns
// the processed config without persisting. The caller is responsible for batch-persisting all changes.
func processSingleLspFolderConfig(ctx context.Context, conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, path types.FilePath, incomingMap map[types.FilePath]types.LspFolderConfig, notifier notification.Notifier, configResolver types.ConfigResolverInterface) singleFolderResult {
	subLogger := logger.With().Str("method", "processSingleLspFolderConfig").Str("path", string(path)).Logger()
	fc := config.GetUnenrichedFolderConfigFromEngine(engine, configResolver, path, logger)

	// Capture old snapshot BEFORE applying updates
	oldSnapshot := types.ReadFolderConfigSnapshot(conf, types.PathKey(path))

	// Validate that the changes are allowed, then apply the new config.
	normalizedPath := fc.FolderPath
	applyChanged := false
	var lockedFields []string
	if incoming, hasIncoming := incomingMap[normalizedPath]; hasIncoming {
		lockedFields = validateLockedFields(configResolver, conf, fc, &incoming, &subLogger)
		applyChanged = fc.ApplyLspUpdate(&incoming)
	}

	// Skip calls to LDX-Sync and feature flag population here during LS init,
	// will be handled explicitly later on during init.
	orgSettingsChanged := false
	if conf.GetBool(types.SettingIsLspInitialized) {
		orgSettingsChanged = updateFolderOrgIfNeeded(ctx, conf, engine, logger, fc, fc, oldSnapshot, notifier)
		mustFeatureFlagServiceFromContext(ctx).PopulateFolderConfig(fc)
	}

	newSnapshot := types.ReadFolderConfigSnapshot(conf, normalizedPath)

	return singleFolderResult{
		config:             *fc,
		oldSnapshot:        oldSnapshot,
		newSnapshot:        newSnapshot,
		configChanged:      applyChanged,
		orgSettingsChanged: orgSettingsChanged,
		lockedFields:       lockedFields,
	}
}

// validateLockedFields checks if any fields in the incoming LspFolderConfig are locked by LDX-Sync.
// Returns the names of rejected (locked) settings so the caller can fold them
// into the single deduplicated locked-fields notification per triggering event
// (see [IDE-1970]).
//
// The resolver is passed in (not fetched via di.ConfigResolver()) so that
// machine-scope and folder-scope validation share the same resolver instance
// when a caller injects one through UpdateSettings/InitializeSettings.
//
// If the incoming update changes PreferredOrg, locks are evaluated against the NEW org's policies
// to prevent bypassing stricter locks during an org switch.
func validateLockedFields(resolver types.ConfigResolverInterface, conf configuration.Configuration, folderConfig *types.FolderConfig, incoming *types.LspFolderConfig, subLogger *zerolog.Logger) []string {
	if resolver == nil || incoming.Settings == nil {
		return nil
	}

	restoreOldOrg := temporarilyApplyNewOrgForValidation(conf, folderConfig, incoming)
	defer func() {
		if restoreOldOrg != nil {
			restoreOldOrg()
		}
	}()

	var locked []string
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
			locked = append(locked, settingName)
			delete(incoming.Settings, settingName)
		}
	}

	return locked
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

func updateFolderOrgIfNeeded(ctx context.Context, conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, fc *types.FolderConfig, folderConfig *types.FolderConfig, oldSnapshot types.FolderConfigSnapshot, notifier notification.Notifier) bool {
	orgSettingsChanged := fc != nil && !folderConfigsOrgSettingsEqual(oldSnapshot, *folderConfig)

	if orgSettingsChanged {
		updateFolderConfigOrg(conf, logger, folderConfig, oldSnapshot)
		ws := config.GetWorkspace(conf)
		folder := ws.GetFolderContaining(folderConfig.FolderPath)
		if folder != nil {
			mustLdxSyncServiceFromContext(ctx).RefreshConfigFromLdxSync(context.Background(), conf, engine, logger, []types.Folder{folder}, notifier)
		}
	}
	return orgSettingsChanged
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
		lspConfig := command.BuildLspConfiguration(conf, engine, logger, nil, configResolver)
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
		types.SetPreferredOrgAndOrgSetByUser(conf, folderConfig.FolderPath, currentSnap.PreferredOrg, true)
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
