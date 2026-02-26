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
	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config/ldx_sync/2024-10-15"
)

// ConfigSource indicates where a configuration value came from
type ConfigSource int

const (
	ConfigSourceDefault ConfigSource = iota
	ConfigSourceGlobal
	ConfigSourceLDXSync
	ConfigSourceLDXSyncEnforced
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
	case ConfigSourceLDXSyncEnforced:
		return "ldx-sync-enforced"
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

// Setting name constants for all LDX-Sync settings.
// Machine- and folder-scope settings that exist in the API enum use the GAF typed constants
// for compile-time validation. Settings not in the API enum (derived or snyk-ls-only) remain as plain strings.
const (
	// Machine-scope settings (from GlobalSettingName API enum)
	SettingApiEndpoint            = string(v20241015.ApiEndpoint)
	SettingCodeEndpoint           = string(v20241015.CodeEndpoint)
	SettingAuthenticationMethod   = string(v20241015.AuthenticationMethod)
	SettingProxyHttp              = string(v20241015.ProxyHttp)
	SettingProxyHttps             = string(v20241015.ProxyHttps)
	SettingProxyNoProxy           = string(v20241015.ProxyNoProxy)
	SettingProxyInsecure          = string(v20241015.ProxyInsecure)
	SettingAutoConfigureMcpServer = string(v20241015.AutoConfigureMcpServer)
	SettingTrustEnabled           = string(v20241015.TrustEnabled)
	SettingBinaryBaseUrl          = string(v20241015.BinaryBaseUrl)
	SettingCliPath                = string(v20241015.CliPath)
	SettingAutomaticDownload      = string(v20241015.AutomaticDownload)
	SettingCliReleaseChannel      = string(v20241015.CliReleaseChannel)

	// Machine-scope settings not in GlobalSettingName API enum (snyk-ls only)
	SettingPublishSecurityAtInceptionRules = "publish_security_at_inception_rules"

	// Org-scope settings (from GlobalSettingName API enum)
	SettingEnabledProducts        = string(v20241015.EnabledProducts)
	SettingEnabledSeverities      = string(v20241015.EnabledSeverities)
	SettingRiskScoreThreshold     = string(v20241015.RiskScoreThreshold)
	SettingCweIds                 = string(v20241015.CweIds)
	SettingCveIds                 = string(v20241015.CveIds)
	SettingRuleIds                = string(v20241015.RuleIds)
	SettingScanAutomatic          = string(v20241015.ScanAutomatic)
	SettingScanNetNew             = string(v20241015.ScanNetNew)
	SettingIssueViewOpenIssues    = string(v20241015.IssueViewOpenIssues)
	SettingIssueViewIgnoredIssues = string(v20241015.IssueViewIgnoredIssues)

	// Org-scope settings derived from enabled_products (not in API enum directly)
	SettingSnykCodeEnabled = "snyk_code_enabled"
	SettingSnykOssEnabled  = "snyk_oss_enabled"
	SettingSnykIacEnabled  = "snyk_iac_enabled"

	// Folder-scope settings (from FolderSettingName API enum)
	SettingReferenceFolder       = string(v20241015.ReferenceFolder)
	SettingReferenceBranch       = string(v20241015.ReferenceBranch)
	SettingAdditionalParameters  = string(v20241015.AdditionalParameters)
	SettingAdditionalEnvironment = string(v20241015.AdditionalEnvironment)
)

// GetSettingScope returns the scope for a given setting name
func GetSettingScope(settingName string) SettingScope {
	if scope, ok := settingScopeByName[settingName]; ok {
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
