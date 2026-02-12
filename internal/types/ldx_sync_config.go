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

	"github.com/erni27/imcache"
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
	IsEnforced  bool   `json:"isEnforced"`
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
func (c *LDXSyncOrgConfig) SetField(settingName string, value any, isLocked, isEnforced bool, originScope string) {
	if c.Fields == nil {
		c.Fields = make(map[string]*LDXSyncField)
	}
	c.Fields[settingName] = &LDXSyncField{
		Value:       value,
		IsLocked:    isLocked,
		IsEnforced:  isEnforced,
		OriginScope: originScope,
	}
}

// LDXSyncConfigCache holds cached LDX-Sync configurations for all organizations.
// All methods are safe for concurrent use (imcache is internally thread-safe).
// Currently no expiry is set; when needed, use imcache.WithExpiration on Set calls.
type LDXSyncConfigCache struct {
	orgConfigs         *imcache.Cache[string, *LDXSyncOrgConfig]
	folderToOrgMapping *imcache.Cache[FilePath, string]
}

// NewLDXSyncConfigCache creates a new empty LDXSyncConfigCache
func NewLDXSyncConfigCache() *LDXSyncConfigCache {
	return &LDXSyncConfigCache{
		orgConfigs:         imcache.New[string, *LDXSyncOrgConfig](),
		folderToOrgMapping: imcache.New[FilePath, string](),
	}
}

// IsEmpty returns true if the cache has no org configs
func (c *LDXSyncConfigCache) IsEmpty() bool {
	if c == nil {
		return true
	}
	return len(c.orgConfigs.GetAll()) == 0
}

// GetOrgConfig returns the config for the given org, or nil if not found
func (c *LDXSyncConfigCache) GetOrgConfig(orgId string) *LDXSyncOrgConfig {
	if c == nil {
		return nil
	}
	val, found := c.orgConfigs.Get(orgId)
	if !found {
		return nil
	}
	return val
}

// SetOrgConfig sets the config for the given org
func (c *LDXSyncConfigCache) SetOrgConfig(orgConfig *LDXSyncOrgConfig) {
	c.orgConfigs.Set(orgConfig.OrgId, orgConfig, imcache.WithNoExpiration())
}

// RemoveOrgConfig removes the config for the given org
func (c *LDXSyncConfigCache) RemoveOrgConfig(orgId string) {
	c.orgConfigs.Remove(orgId)
}

// SetFolderOrg sets the org ID for a folder path.
// The path is automatically normalized using PathKey for cross-platform consistency.
func (c *LDXSyncConfigCache) SetFolderOrg(folderPath FilePath, orgId string) {
	c.folderToOrgMapping.Set(PathKey(folderPath), orgId, imcache.WithNoExpiration())
}

// GetOrgIdForFolder returns the org ID for a folder path from the cache,
// or empty string if not found. This only returns what LDX-Sync determined,
// not a fallback value. Fallback logic should happen at the point of use.
// The path is automatically normalized using PathKey for cross-platform consistency.
func (c *LDXSyncConfigCache) GetOrgIdForFolder(folderPath FilePath) string {
	if c == nil {
		return ""
	}
	val, found := c.folderToOrgMapping.Get(PathKey(folderPath))
	if !found {
		return ""
	}
	return val
}

// ClearFolderOrgMapping clears all folder-to-org mappings
func (c *LDXSyncConfigCache) ClearFolderOrgMapping() {
	c.folderToOrgMapping.RemoveAll()
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

	// Org-scope settings
	SettingEnabledSeverities      = "enabled_severities"
	SettingRiskScoreThreshold     = "risk_score_threshold"
	SettingCweIds                 = "cwe_ids"
	SettingCveIds                 = "cve_ids"
	SettingRuleIds                = "rule_ids"
	SettingSnykCodeEnabled        = "snyk_code_enabled"
	SettingSnykOssEnabled         = "snyk_oss_enabled"
	SettingSnykIacEnabled         = "snyk_iac_enabled"
	SettingScanAutomatic          = "scan_automatic"
	SettingScanNetNew             = "scan_net_new"
	SettingIssueViewOpenIssues    = "issue_view_open_issues"
	SettingIssueViewIgnoredIssues = "issue_view_ignored_issues"

	// Folder-scope settings
	SettingReferenceFolder       = "reference_folder"
	SettingReferenceBranch       = "reference_branch"
	SettingAdditionalParameters  = "additional_parameters"
	SettingAdditionalEnvironment = "additional_environment"
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

	// Org-scope settings
	SettingEnabledSeverities:      SettingScopeOrg,
	SettingRiskScoreThreshold:     SettingScopeOrg,
	SettingCweIds:                 SettingScopeOrg,
	SettingCveIds:                 SettingScopeOrg,
	SettingRuleIds:                SettingScopeOrg,
	SettingSnykCodeEnabled:        SettingScopeOrg,
	SettingSnykOssEnabled:         SettingScopeOrg,
	SettingSnykIacEnabled:         SettingScopeOrg,
	SettingScanAutomatic:          SettingScopeOrg,
	SettingScanNetNew:             SettingScopeOrg,
	SettingIssueViewOpenIssues:    SettingScopeOrg,
	SettingIssueViewIgnoredIssues: SettingScopeOrg,

	// Folder-scope settings
	SettingReferenceFolder:       SettingScopeFolder,
	SettingReferenceBranch:       SettingScopeFolder,
	SettingAdditionalParameters:  SettingScopeFolder,
	SettingAdditionalEnvironment: SettingScopeFolder,
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
