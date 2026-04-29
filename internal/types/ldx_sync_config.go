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
const DefaultSnykApiUrl = "https://api.snyk.io"

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
	SettingSecureAtInceptionExecutionFreq  = "secure_at_inception_execution_frequency"
	SettingTrustEnabled                    = "trust_enabled"
	SettingBinaryBaseUrl                   = "binary_base_url"
	SettingCliPath                         = "cli_path"
	SettingAutomaticDownload               = "automatic_download"
	SettingCliReleaseChannel               = "cli_release_channel"
	SettingOrganization                    = "organization"
	SettingAutomaticAuthentication         = "automatic_authentication"

	SettingTrustedFolders               = "trusted_folders"
	SettingToken                        = "token"
	SettingSendErrorReports             = "send_error_reports"
	SettingEnableSnykLearnCodeActions   = "enable_snyk_learn_code_actions"
	SettingEnableSnykOssQuickFixActions = "enable_snyk_oss_quick_fix_code_actions"
	SettingEnableSnykOpenBrowserActions = "enable_snyk_open_browser_actions"

	// Folder (in repository) scope settings
	SettingSeverityFilterCritical = "severity_filter_critical"
	SettingSeverityFilterHigh     = "severity_filter_high"
	SettingSeverityFilterMedium   = "severity_filter_medium"
	SettingSeverityFilterLow      = "severity_filter_low"
	SettingSnykAdvisorEnabled     = "snyk_advisor_enabled"
	SettingEnabledSeverities      = "enabled_severities"
	SettingRiskScoreThreshold     = "risk_score_threshold"
	SettingCweIds                 = "cwe_ids"
	SettingCveIds                 = "cve_ids"
	SettingRuleIds                = "rule_ids"
	SettingSnykCodeEnabled        = "snyk_code_enabled"
	SettingSnykOssEnabled         = "snyk_oss_enabled"
	SettingSnykIacEnabled         = "snyk_iac_enabled"
	SettingSnykSecretsEnabled     = "snyk_secrets_enabled"
	SettingScanAutomatic          = "scan_automatic"
	SettingScanNetNew             = "scan_net_new"
	SettingIssueViewOpenIssues    = "issue_view_open_issues"
	SettingIssueViewIgnoredIssues = "issue_view_ignored_issues"
	SettingReferenceFolder        = "reference_folder"
	SettingReferenceBranch        = "reference_branch"
	SettingAdditionalParameters   = "additional_parameters"
	SettingAdditionalEnvironment  = "additional_environment"
	SettingBaseBranch             = "base_branch"
	SettingLocalBranches          = "local_branches"
	SettingPreferredOrg           = "preferred_org"
	SettingAutoDeterminedOrg      = "auto_determined_org"
	SettingOrgSetByUser           = "org_set_by_user"
	SettingScanCommandConfig      = "scan_command_config"
	SettingSastSettings           = "sast_settings"

	// Internal settings (not registered as pflag, but stored in GAF configuration)
	SettingSnykCodeAnalysisTimeout    = "snyk_code_analysis_timeout"
	SettingBinarySearchPaths          = "binary_search_paths"
	SettingConfigFile                 = "config_file"
	SettingFormat                     = "format"
	SettingHoverVerbosity             = "hover_verbosity"
	SettingDeviceId                   = "device_id"
	SettingLogPath                    = "log_path"
	SettingLastSetOrganization        = "last_set_organization"
	SettingCachedOriginalPath         = "cached_original_path"
	SettingUserSettingsPath           = "user_settings_path"
	SettingIsLspInitialized           = "is_lsp_initialized"
	SettingFolderConfigsInitialized   = "folder_configs_initialized"
	SettingClientCapabilities         = "client_capabilities"
	SettingClientProtocolVersion      = "client_protocol_version"
	SettingOsPlatform                 = "os_platform"
	SettingOsArch                     = "os_arch"
	SettingRuntimeName                = "runtime_name"
	SettingRuntimeVersion             = "runtime_version"
	SettingCliAdditionalOssParameters = "cli_additional_oss_parameters"
	SettingOffline                    = "offline"
	SettingWorkspace                  = "workspace"
	SettingDefaultEnvReadyChannel     = "default_env_ready_channel"
	// SettingConfigFileLegacy is the GAF-internal key for the config file path.
	// GAF reads this key natively; we also write to UserGlobalKey(SettingConfigFile) for precedence.
	SettingConfigFileLegacy = "configfile"
)
