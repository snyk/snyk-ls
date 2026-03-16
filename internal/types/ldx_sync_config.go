/*
 * © 2026 Snyk Limited
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

package types

import (
	"time"
)

// ConfigSource indicates where a configuration value came from
type ConfigSource int

const (
	ConfigSourceDefault ConfigSource = iota
	ConfigSourceGlobal
	ConfigSourceLDXSync
	ConfigSourceLDXSyncLocked
	ConfigSourceUserOverride
	ConfigSourceFolder
)

func (cs ConfigSource) String() string {
	switch cs {
	case ConfigSourceDefault:
		return "default"
	case ConfigSourceGlobal:
		return "global"
	case ConfigSourceLDXSync:
		return "ldx-sync"
	case ConfigSourceLDXSyncLocked:
		return "ldx-sync-locked"
	case ConfigSourceUserOverride:
		return "user-override"
	case ConfigSourceFolder:
		return "folder"
	default:
		return "unknown"
	}
}

// SettingScope indicates the scope of a setting
type SettingScope int

const (
	SettingScopeMachine SettingScope = iota
	SettingScopeOrg
	SettingScopeFolder
)

func (ss SettingScope) String() string {
	switch ss {
	case SettingScopeMachine:
		return "machine"
	case SettingScopeOrg:
		return "org"
	case SettingScopeFolder:
		return "folder"
	default:
		return "unknown"
	}
}

// LDXSyncField represents a single field from LDX-Sync with its metadata
type LDXSyncField struct {
	Value       any    `json:"value"`
	IsLocked    bool   `json:"isLocked"`
	OriginScope string `json:"originScope,omitempty"`
}

// LDXSyncOrgConfig represents the LDX-Sync configuration for a single organization
type LDXSyncOrgConfig struct {
	OrgId     string                   `json:"orgId"`
	FetchedAt time.Time                `json:"fetchedAt"`
	Fields    map[string]*LDXSyncField `json:"fields"`
}

// NewLDXSyncOrgConfig creates a new LDXSyncOrgConfig for the given org
func NewLDXSyncOrgConfig(orgId string) *LDXSyncOrgConfig {
	return &LDXSyncOrgConfig{
		OrgId:     orgId,
		FetchedAt: time.Now(),
		Fields:    make(map[string]*LDXSyncField),
	}
}

// GetField returns the field for the given setting name, or nil if not found
func (c *LDXSyncOrgConfig) GetField(settingName string) *LDXSyncField {
	if c == nil || c.Fields == nil {
		return nil
	}
	return c.Fields[settingName]
}

// SetField sets a field value with its metadata
func (c *LDXSyncOrgConfig) SetField(settingName string, value any, isLocked bool, originScope string) {
	if c.Fields == nil {
		c.Fields = make(map[string]*LDXSyncField)
	}
	c.Fields[settingName] = &LDXSyncField{
		Value:       value,
		IsLocked:    isLocked,
		OriginScope: originScope,
	}
}

// Setting name constants for all LDX-Sync settings
const (
	// Machine-scope settings
	SettingApiEndpoint                     = "api_endpoint"
	SettingCodeEndpoint                    = "code_endpoint"
	SettingAuthenticationMethod            = "authentication_method"
	SettingProxyHttp                       = "proxy_http"
	SettingProxyHttps                      = "proxy_https"
	SettingProxyNoProxy                    = "proxy_no_proxy"
	SettingProxyInsecure                   = "proxy_insecure"
	SettingAutoConfigureMcpServer          = "auto_configure_mcp_server"
	SettingPublishSecurityAtInceptionRules = "publish_security_at_inception_rules"
	SettingTrustEnabled                    = "trust_enabled"
	SettingBinaryBaseUrl                   = "binary_base_url"
	SettingCliPath                         = "cli_path"
	SettingAutomaticDownload               = "automatic_download"
	SettingCliReleaseChannel               = "cli_release_channel"
	SettingOrganization                    = "organization"
	SettingAutomaticAuthentication         = "automatic_authentication"
	SettingToken                           = "token"
	SettingSendErrorReports                = "send_error_reports"
	SettingEnableSnykLearnCodeActions      = "enable_snyk_learn_code_actions"
	SettingEnableSnykOssQuickFixActions    = "enable_snyk_oss_quick_fix_code_actions"
	SettingEnableSnykOpenBrowserActions    = "enable_snyk_open_browser_actions"

	// Org-scope settings
	SettingEnabledSeverities      = "enabled_severities"
	SettingRiskScoreThreshold     = "risk_score_threshold"
	SettingCweIds                 = "cwe_ids"
	SettingCveIds                 = "cve_ids"
	SettingRuleIds                = "rule_ids"
	SettingSnykCodeEnabled        = "snyk_code_enabled"
	SettingSnykOssEnabled         = "snyk_oss_enabled"
	SettingSnykIacEnabled         = "snyk_iac_enabled"
	SettingSnykContainerEnabled   = "snyk_container_enabled"
	SettingSnykSecretsEnabled     = "snyk_secrets_enabled"
	SettingScanAutomatic          = "scan_automatic"
	SettingScanNetNew             = "scan_net_new"
	SettingIssueViewOpenIssues    = "issue_view_open_issues"
	SettingIssueViewIgnoredIssues = "issue_view_ignored_issues"

	// Folder-scope settings
	SettingReferenceFolder       = "reference_folder"
	SettingReferenceBranch       = "reference_branch"
	SettingAdditionalParameters  = "additional_parameters"
	SettingAdditionalEnvironment = "additional_environment"
	SettingBaseBranch            = "base_branch"
	SettingLocalBranches         = "local_branches"
	SettingPreferredOrg          = "preferred_org"
	SettingAutoDeterminedOrg     = "auto_determined_org"
	SettingOrgSetByUser          = "org_set_by_user"
	SettingScanCommandConfig     = "scan_command_config"
	SettingSastSettings          = "sast_settings"
	SettingPreAssignedOrgId      = "pre_assigned_org_id"

	// Internal settings (not registered as pflag, but stored in GAF configuration)
	SettingSnykCodeAnalysisTimeout        = "snyk_code_analysis_timeout"
	SettingBinarySearchPaths              = "binary_search_paths"
	SettingConfigFile                     = "config_file"
	SettingFormat                         = "format"
	SettingSeverityFilterCritical         = "severity_filter_critical"
	SettingSeverityFilterHigh             = "severity_filter_high"
	SettingSeverityFilterMedium           = "severity_filter_medium"
	SettingSeverityFilterLow              = "severity_filter_low"
	SettingHoverVerbosity                 = "hover_verbosity"
	SettingDeviceId                       = "device_id"
	SettingLogPath                        = "log_path"
	SettingLastSetOrganization            = "last_set_organization"
	SettingCachedOriginalPath             = "cached_original_path"
	SettingCliInsecure                    = "cli_insecure"
	SettingTrustedFolders                 = "trusted_folders"
	SettingUserSettingsPath               = "user_settings_path"
	SettingIsLspInitialized               = "is_lsp_initialized"
	SettingClientCapabilities             = "client_capabilities"
	SettingClientProtocolVersion          = "client_protocol_version"
	SettingOsPlatform                     = "os_platform"
	SettingOsArch                         = "os_arch"
	SettingRuntimeName                    = "runtime_name"
	SettingRuntimeVersion                 = "runtime_version"
	SettingCliAdditionalOssParameters     = "cli_additional_oss_parameters"
	SettingSnykAdvisorEnabled             = "snyk_advisor_enabled"
	SettingSecureAtInceptionExecutionFreq = "secure_at_inception_execution_frequency"
	SettingOffline                        = "offline"
	SettingWorkspace                      = "workspace"
	SettingDefaultEnvReadyChannel         = "default_env_ready_channel"
	// SettingConfigFileLegacy is the GAF-internal key for the config file path.
	// GAF reads this key natively; we also write to UserGlobalKey(SettingConfigFile) for precedence.
	SettingConfigFileLegacy = "configfile"
)

// settingScopeRegistry maps setting names to their scopes
var settingScopeRegistry = map[string]SettingScope{
	// Machine-scope settings
	SettingApiEndpoint:                     SettingScopeMachine,
	SettingCodeEndpoint:                    SettingScopeMachine,
	SettingAuthenticationMethod:            SettingScopeMachine,
	SettingProxyHttp:                       SettingScopeMachine,
	SettingProxyHttps:                      SettingScopeMachine,
	SettingProxyNoProxy:                    SettingScopeMachine,
	SettingProxyInsecure:                   SettingScopeMachine,
	SettingAutoConfigureMcpServer:          SettingScopeMachine,
	SettingPublishSecurityAtInceptionRules: SettingScopeMachine,
	SettingTrustEnabled:                    SettingScopeMachine,
	SettingBinaryBaseUrl:                   SettingScopeMachine,
	SettingCliPath:                         SettingScopeMachine,
	SettingAutomaticDownload:               SettingScopeMachine,
	SettingCliReleaseChannel:               SettingScopeMachine,
	SettingOrganization:                    SettingScopeMachine,
	SettingAutomaticAuthentication:         SettingScopeMachine,
	SettingToken:                           SettingScopeMachine,
	SettingSendErrorReports:                SettingScopeMachine,
	SettingEnableSnykLearnCodeActions:      SettingScopeMachine,
	SettingEnableSnykOssQuickFixActions:    SettingScopeMachine,
	SettingEnableSnykOpenBrowserActions:    SettingScopeMachine,
	SettingCliInsecure:                     SettingScopeMachine,
	SettingFormat:                          SettingScopeMachine,
	SettingDeviceId:                        SettingScopeMachine,
	SettingOffline:                         SettingScopeMachine,
	SettingUserSettingsPath:                SettingScopeMachine,
	SettingHoverVerbosity:                  SettingScopeMachine,
	SettingClientProtocolVersion:           SettingScopeMachine,
	SettingOsPlatform:                      SettingScopeMachine,
	SettingOsArch:                          SettingScopeMachine,
	SettingRuntimeName:                     SettingScopeMachine,
	SettingRuntimeVersion:                  SettingScopeMachine,
	SettingTrustedFolders:                  SettingScopeMachine,
	SettingSecureAtInceptionExecutionFreq:  SettingScopeMachine,

	// Org-scope settings
	SettingEnabledSeverities:      SettingScopeOrg,
	SettingRiskScoreThreshold:     SettingScopeOrg,
	SettingCweIds:                 SettingScopeOrg,
	SettingCveIds:                 SettingScopeOrg,
	SettingRuleIds:                SettingScopeOrg,
	SettingSnykCodeEnabled:        SettingScopeOrg,
	SettingSnykOssEnabled:         SettingScopeOrg,
	SettingSnykIacEnabled:         SettingScopeOrg,
	SettingSnykContainerEnabled:   SettingScopeOrg,
	SettingSnykSecretsEnabled:     SettingScopeOrg,
	SettingScanAutomatic:          SettingScopeOrg,
	SettingScanNetNew:             SettingScopeOrg,
	SettingIssueViewOpenIssues:    SettingScopeOrg,
	SettingIssueViewIgnoredIssues: SettingScopeOrg,

	// Folder-scope settings
	SettingReferenceFolder:            SettingScopeFolder,
	SettingReferenceBranch:            SettingScopeFolder,
	SettingAdditionalParameters:       SettingScopeFolder,
	SettingCliAdditionalOssParameters: SettingScopeFolder,
	SettingAdditionalEnvironment:      SettingScopeFolder,
	SettingBaseBranch:                 SettingScopeFolder,
	SettingLocalBranches:              SettingScopeFolder,
	SettingPreferredOrg:               SettingScopeFolder,
	SettingAutoDeterminedOrg:          SettingScopeFolder,
	SettingOrgSetByUser:               SettingScopeFolder,
	SettingScanCommandConfig:          SettingScopeFolder,
	SettingSastSettings:               SettingScopeFolder,
	SettingPreAssignedOrgId:           SettingScopeFolder,
}

// GetSettingScope returns the scope for a given setting name
func GetSettingScope(settingName string) SettingScope {
	if scope, ok := settingScopeRegistry[settingName]; ok {
		return scope
	}
	return SettingScopeOrg
}

// IsMachineWideSetting returns true if the setting is machine-scoped
func IsMachineWideSetting(settingName string) bool {
	return GetSettingScope(settingName) == SettingScopeMachine
}

// IsOrgScopedSetting returns true if the setting is org-scoped
func IsOrgScopedSetting(settingName string) bool {
	return GetSettingScope(settingName) == SettingScopeOrg
}

// IsFolderScopedSetting returns true if the setting is folder-scoped
func IsFolderScopedSetting(settingName string) bool {
	return GetSettingScope(settingName) == SettingScopeFolder
}

// writeOnlySettingNames are accepted IDE→LS but NOT sent LS→IDE (config.writeOnly annotation)
var writeOnlySettingNames = []string{
	SettingToken, SettingSendErrorReports, SettingEnableSnykLearnCodeActions,
	SettingEnableSnykOssQuickFixActions, SettingEnableSnykOpenBrowserActions,
}

// IsWriteOnlySetting returns true if the setting should not be sent in LS→IDE notifications
func IsWriteOnlySetting(settingName string) bool {
	for _, n := range writeOnlySettingNames {
		if n == settingName {
			return true
		}
	}
	return false
}
