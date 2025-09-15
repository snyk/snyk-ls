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

package ldx_sync

import (
	"reflect"

	ldx_sync_config "github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils/ldx_sync"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
)

// SyncConfiguration syncs LDX-Sync configuration to the Language Server configuration
func SyncConfiguration(c *config.Config) {
	c.Logger().Debug().Msg("Syncing LDX-Sync configuration")

	// Get the LDX-Sync configuration from the engine
	ldxConfig := c.Engine().GetConfiguration().Get(ldx_sync.LDX_SYNC_CONFIG)
	if ldxConfig == nil {
		c.Logger().Debug().Msg("No LDX-Sync configuration available")
		return
	}

	// Cast to the proper type - now using the high-level Configuration struct
	config, ok := ldxConfig.(*ldx_sync_config.Configuration)
	if !ok {
		c.Logger().Warn().Msg("Failed to cast LDX-Sync configuration to expected type")
		return
	}

	// Sync organization
	SyncOrganization(c, config)

	// Sync authentication and endpoints
	SyncAuthenticationMethod(c, config)
	SyncEndpoints(c, config)

	// Sync filter configuration
	SyncFilterConfig(c, config)

	// Sync folder configurations
	SyncFolderConfigs(c, config)

	// Sync IDE configuration
	SyncIdeConfig(c, config)

	// Sync complete organizations
	SyncCompleteOrganizations(c, config)

	// Sync configuration metadata
	SyncAttributeSource(c, config)
	SyncTimestamps(c, config)
	SyncScope(c, config)
	SyncPolicy(c, config)

	// Sync proxy configuration
	SyncProxyConfig(c, config)

	c.Logger().Debug().Msg("LDX-Sync configuration sync completed")
}

// SyncOrganization syncs organization settings from LDX-Sync configuration
func SyncOrganization(c *config.Config, config *ldx_sync_config.Configuration) {
	if config.Organization == "" {
		return
	}

	oldOrgId := c.Organization()
	c.SetOrganization(config.Organization)
	if oldOrgId != config.Organization {
		c.Logger().Info().Str("oldOrgId", oldOrgId).Str("newOrgId", config.Organization).Msg("Organization updated from LDX-Sync")
	}
}

// SyncFilterConfig syncs filter configuration from LDX-Sync configuration
func SyncFilterConfig(c *config.Config, config *ldx_sync_config.Configuration) {
	// Sync from legacy SeverityFilter field
	if config.SeverityFilter != nil {
		oldFilter := c.FilterSeverity()
		newFilter := types.SeverityFilter{
			Critical: config.SeverityFilter.Critical,
			High:     config.SeverityFilter.High,
			Medium:   config.SeverityFilter.Medium,
			Low:      config.SeverityFilter.Low,
		}

		if !reflect.DeepEqual(oldFilter, newFilter) {
			c.SetSeverityFilter(&newFilter)
			c.Logger().Info().Interface("severityFilter", newFilter).Msg("Severity filter updated from LDX-Sync")
		}
	}

	// Sync from complete FilterConfig if available
	if config.FilterConfig != nil {
		SyncCompleteFilterConfig(c, config.FilterConfig)
	}
}

// SyncIdeConfig syncs IDE configuration from LDX-Sync configuration
func SyncIdeConfig(c *config.Config, config *ldx_sync_config.Configuration) {
	// Sync product configuration (from both old and new locations)
	if config.ProductConfig != nil {
		SyncProductConfig(c, config.ProductConfig)
	}

	// Sync scan configuration (from both old and new locations)
	SyncScanConfig(c, config.AutoScan)

	// Sync trust configuration (from both old and new locations)
	if len(config.TrustedFolders) > 0 {
		SyncTrustConfig(c, config.TrustedFolders)
	}

	// Sync complete IDE configuration if available
	if config.IdeConfig != nil {
		SyncCompleteIdeConfig(c, config.IdeConfig)
	}
}

// SyncProductConfig syncs product configuration from LDX-Sync configuration
func SyncProductConfig(c *config.Config, productConfig *ldx_sync_config.ProductConfig) {
	// Sync individual product settings
	oldCodeEnabled := c.IsSnykCodeEnabled()
	if oldCodeEnabled != productConfig.Code {
		c.SetSnykCodeEnabled(productConfig.Code)
		c.Logger().Info().Bool("snykCodeEnabled", productConfig.Code).Msg("Snyk Code enabled updated from LDX-Sync")
	}

	oldOssEnabled := c.IsSnykOssEnabled()
	if oldOssEnabled != productConfig.Oss {
		c.SetSnykOssEnabled(productConfig.Oss)
		c.Logger().Info().Bool("snykOssEnabled", productConfig.Oss).Msg("Snyk OSS enabled updated from LDX-Sync")
	}

	oldIacEnabled := c.IsSnykIacEnabled()
	if oldIacEnabled != productConfig.Iac {
		c.SetSnykIacEnabled(productConfig.Iac)
		c.Logger().Info().Bool("snykIacEnabled", productConfig.Iac).Msg("Snyk IaC enabled updated from LDX-Sync")
	}
}

// SyncScanConfig syncs scan configuration from LDX-Sync configuration
func SyncScanConfig(c *config.Config, autoScan bool) {
	oldAutoScan := c.IsAutoScanEnabled()
	if oldAutoScan != autoScan {
		c.SetAutomaticScanning(autoScan)
		c.Logger().Info().Bool("automaticScanning", autoScan).Msg("Automatic scanning updated from LDX-Sync")
	}
}

// SyncTrustConfig syncs trust configuration from LDX-Sync configuration
func SyncTrustConfig(c *config.Config, trustedFolders []string) {
	// Convert []string to []types.FilePath
	var filePaths []types.FilePath
	for _, folder := range trustedFolders {
		filePaths = append(filePaths, types.FilePath(folder))
	}

	oldTrustedFolders := c.TrustedFolders()
	if !reflect.DeepEqual(oldTrustedFolders, filePaths) {
		c.SetTrustedFolders(filePaths)
		c.Logger().Info().Interface("trustedFolders", filePaths).Msg("Trusted folders updated from LDX-Sync")
	}
}

// SyncProxyConfig syncs proxy configuration from LDX-Sync configuration
func SyncProxyConfig(c *config.Config, config *ldx_sync_config.Configuration) {
	if config.ProxyConfig == nil {
		return
	}

	// Note: Proxy configuration methods are not available in the current Config interface
	// This is a placeholder for future implementation when proxy methods are added
	c.Logger().Debug().Interface("proxyConfig", config.ProxyConfig).Msg("Proxy configuration sync not yet implemented - methods not available in Config interface")
}

// SyncAuthenticationMethod syncs authentication method from LDX-Sync configuration
func SyncAuthenticationMethod(c *config.Config, config *ldx_sync_config.Configuration) {
	if config.AuthenticationMethod == nil {
		return
	}

	// Convert string to AuthenticationMethod enum
	var authMethod types.AuthenticationMethod
	switch *config.AuthenticationMethod {
	case "oauth":
		authMethod = types.OAuthAuthentication
	case "token":
		authMethod = types.TokenAuthentication
	case "pat":
		authMethod = types.PatAuthentication
	default:
		c.Logger().Warn().Str("authMethod", *config.AuthenticationMethod).Msg("Unknown authentication method from LDX-Sync")
		return
	}

	oldAuthMethod := c.AuthenticationMethod()
	if oldAuthMethod != authMethod {
		c.SetAuthenticationMethod(authMethod)
		c.Logger().Info().Str("authMethod", *config.AuthenticationMethod).Msg("Authentication method updated from LDX-Sync")
	}
}

// SyncEndpoints syncs API endpoints from LDX-Sync configuration
func SyncEndpoints(c *config.Config, config *ldx_sync_config.Configuration) {
	if config.Endpoints == nil {
		return
	}

	// Sync Snyk Code API endpoint
	if config.Endpoints.CodeEndpoint != nil {
		oldCodeApi := c.SnykCodeApi()
		if oldCodeApi != *config.Endpoints.CodeEndpoint {
			c.SetSnykCodeApi(*config.Endpoints.CodeEndpoint)
			c.Logger().Info().Str("codeApi", *config.Endpoints.CodeEndpoint).Msg("Snyk Code API endpoint updated from LDX-Sync")
		}
	}

	// Note: Snyk API endpoint sync not available in current Config interface
	if config.Endpoints.ApiEndpoint != nil {
		c.Logger().Debug().Str("apiEndpoint", *config.Endpoints.ApiEndpoint).Msg("Snyk API endpoint sync not yet implemented - method not available in Config interface")
	}
}

// SyncFolderConfigs syncs folder configurations from LDX-Sync configuration
func SyncFolderConfigs(c *config.Config, config *ldx_sync_config.Configuration) {
	if len(config.FolderConfigs) == 0 {
		return
	}

	// Log folder configurations for debugging
	c.Logger().Debug().Int("folderCount", len(config.FolderConfigs)).Msg("Folder configurations available from LDX-Sync")

	// Process each folder configuration
	for i, folderConfig := range config.FolderConfigs {
		c.Logger().Debug().
			Int("folderIndex", i).
			Str("folderPath", folderConfig.FolderPath).
			Str("remoteUrl", folderConfig.RemoteUrl).
			Int("orgCount", len(folderConfig.Organizations)).
			Msg("Processing folder configuration from LDX-Sync")

		// Sync integration information from folder config if available
		SyncFolderIntegrationInfo(c, folderConfig)

		// Sync additional environment variables
		if len(folderConfig.AdditionalEnvironment) > 0 {
			c.Logger().Debug().
				Strs("envVars", folderConfig.AdditionalEnvironment).
				Msg("Additional environment variables available from LDX-Sync folder config")
		}

		// Sync additional parameters
		if len(folderConfig.AdditionalParameters) > 0 {
			c.Logger().Debug().
				Strs("parameters", folderConfig.AdditionalParameters).
				Msg("Additional CLI parameters available from LDX-Sync folder config")
		}

		// Sync pre/post scan commands
		if folderConfig.PreScanExecuteCommand != nil {
			c.Logger().Debug().
				Str("preScanCommand", *folderConfig.PreScanExecuteCommand).
				Msg("Pre-scan execute command available from LDX-Sync folder config")
		}

		if folderConfig.PostScanExecuteCommand != nil {
			c.Logger().Debug().
				Str("postScanCommand", *folderConfig.PostScanExecuteCommand).
				Msg("Post-scan execute command available from LDX-Sync folder config")
		}

		// Sync reference branch/folder
		if folderConfig.ReferenceBranch != nil {
			c.Logger().Debug().
				Str("referenceBranch", *folderConfig.ReferenceBranch).
				Msg("Reference branch available from LDX-Sync folder config")
		}

		if folderConfig.ReferenceFolder != nil {
			c.Logger().Debug().
				Str("referenceFolder", *folderConfig.ReferenceFolder).
				Msg("Reference folder available from LDX-Sync folder config")
		}
	}
}

// SyncCompleteOrganizations syncs complete organization data from LDX-Sync configuration
func SyncCompleteOrganizations(c *config.Config, config *ldx_sync_config.Configuration) {
	if len(config.Organizations) == 0 {
		return
	}

	// Log organization information
	c.Logger().Debug().Int("orgCount", len(config.Organizations)).Msg("Complete organization data available from LDX-Sync")

	for i, org := range config.Organizations {
		c.Logger().Debug().
			Int("orgIndex", i).
			Str("orgId", org.Id).
			Str("orgName", org.Name).
			Str("orgSlug", org.Slug).
			Bool("isDefault", org.IsDefault != nil && *org.IsDefault).
			Bool("preferredByAlgorithm", org.PreferredByAlgorithm != nil && *org.PreferredByAlgorithm).
			Int("projectCount", getIntValue(org.ProjectCount)).
			Msg("Organization details from LDX-Sync")
	}
}

// SyncAttributeSource syncs attribute source information from LDX-Sync configuration
func SyncAttributeSource(c *config.Config, config *ldx_sync_config.Configuration) {
	if config.AttributeSource == nil {
		return
	}

	// Log attribute source information for debugging
	c.Logger().Debug().
		Strs("assetSources", config.AttributeSource.Asset).
		Strs("groupSources", config.AttributeSource.Group).
		Strs("orgSources", config.AttributeSource.Org).
		Strs("projectNameSources", config.AttributeSource.ProjectName).
		Strs("remoteUrlSources", config.AttributeSource.RemoteUrl).
		Strs("tenantSources", config.AttributeSource.Tenant).
		Msg("Configuration attribute sources from LDX-Sync")
}

// SyncTimestamps syncs timestamp information from LDX-Sync configuration
func SyncTimestamps(c *config.Config, config *ldx_sync_config.Configuration) {
	if config.CreatedAt != nil {
		c.Logger().Debug().
			Time("createdAt", *config.CreatedAt).
			Msg("Configuration created timestamp from LDX-Sync")
	}

	if config.LastModifiedAt != nil {
		c.Logger().Debug().
			Time("lastModifiedAt", *config.LastModifiedAt).
			Msg("Configuration last modified timestamp from LDX-Sync")
	}
}

// SyncScope syncs scope information from LDX-Sync configuration
func SyncScope(c *config.Config, config *ldx_sync_config.Configuration) {
	if config.Scope != nil {
		c.Logger().Debug().
			Str("scope", *config.Scope).
			Msg("Configuration scope from LDX-Sync")
	}
}

// SyncPolicy syncs policy information from LDX-Sync configuration
func SyncPolicy(c *config.Config, config *ldx_sync_config.Configuration) {
	if config.Policy == nil {
		return
	}

	// Log policy information for debugging
	c.Logger().Debug().
		Strs("enforcedAttributes", config.Policy.EnforcedAttributes).
		Strs("lockedAttributes", config.Policy.LockedAttributes).
		Msg("Configuration policy from LDX-Sync")
}

// SyncCompleteFilterConfig syncs complete filter configuration from LDX-Sync configuration
func SyncCompleteFilterConfig(c *config.Config, filterConfig *ldx_sync_config.FilterConfig) {
	// Log additional filter configuration for debugging
	if len(filterConfig.Cve) > 0 {
		c.Logger().Debug().Strs("cveFilters", filterConfig.Cve).Msg("CVE filters available from LDX-Sync")
	}

	if len(filterConfig.Cwe) > 0 {
		c.Logger().Debug().Strs("cweFilters", filterConfig.Cwe).Msg("CWE filters available from LDX-Sync")
	}

	if filterConfig.RiskScoreThreshold != nil {
		c.Logger().Debug().Int("riskScoreThreshold", *filterConfig.RiskScoreThreshold).Msg("Risk score threshold available from LDX-Sync")
	}

	if len(filterConfig.Rule) > 0 {
		c.Logger().Debug().Strs("ruleFilters", filterConfig.Rule).Msg("Rule filters available from LDX-Sync")
	}

	// Sync severities from complete filter config if available
	if filterConfig.Severities != nil {
		oldFilter := c.FilterSeverity()
		newFilter := types.SeverityFilter{
			Critical: filterConfig.Severities.Critical,
			High:     filterConfig.Severities.High,
			Medium:   filterConfig.Severities.Medium,
			Low:      filterConfig.Severities.Low,
		}

		if !reflect.DeepEqual(oldFilter, newFilter) {
			c.SetSeverityFilter(&newFilter)
			c.Logger().Info().Interface("severityFilter", newFilter).Msg("Severity filter updated from LDX-Sync complete filter config")
		}
	}
}

// SyncCompleteIdeConfig syncs complete IDE configuration from LDX-Sync configuration
func SyncCompleteIdeConfig(c *config.Config, ideConfig *ldx_sync_config.IdeConfig) {
	// Sync binary management configuration
	if ideConfig.BinaryManagementConfig != nil {
		SyncBinaryManagementConfig(c, ideConfig.BinaryManagementConfig)
	}

	// Sync code actions
	if ideConfig.CodeActions != nil {
		SyncCodeActions(c, ideConfig.CodeActions)
	}

	// Sync hover verbosity
	if ideConfig.HoverVerbosity != nil {
		SyncHoverVerbosity(c, *ideConfig.HoverVerbosity)
	}

	// Sync issue view configuration
	if ideConfig.IssueViewConfig != nil {
		SyncIssueViewConfig(c, ideConfig.IssueViewConfig)
	}

	// Sync product configuration from IDE config
	if ideConfig.ProductConfig != nil {
		SyncProductConfig(c, ideConfig.ProductConfig)
	}

	// Sync scan configuration from IDE config
	if ideConfig.ScanConfig != nil {
		SyncCompleteScanConfig(c, ideConfig.ScanConfig)
	}

	// Sync trust configuration from IDE config
	if ideConfig.TrustConfig != nil {
		SyncCompleteTrustConfig(c, ideConfig.TrustConfig)
	}
}

// SyncBinaryManagementConfig syncs binary management configuration from LDX-Sync configuration
func SyncBinaryManagementConfig(c *config.Config, bmConfig *ldx_sync_config.BinaryManagementConfig) {
	// Sync automatic download setting
	if bmConfig.AutomaticDownload != nil {
		oldAutoDownload := c.ManageBinariesAutomatically()
		if oldAutoDownload != *bmConfig.AutomaticDownload {
			c.SetManageBinariesAutomatically(*bmConfig.AutomaticDownload)
			c.Logger().Info().Bool("automaticDownload", *bmConfig.AutomaticDownload).Msg("Binary management automatic download updated from LDX-Sync")
		}
	}

	// Log CLI path if available
	if bmConfig.CliPath != nil {
		c.Logger().Debug().Str("cliPath", *bmConfig.CliPath).Msg("CLI path available from LDX-Sync binary management config")
	}
}

// SyncCodeActions syncs code actions configuration from LDX-Sync configuration
func SyncCodeActions(c *config.Config, codeActions *ldx_sync_config.CodeActions) {
	// Sync open browser actions
	if len(codeActions.OpenBrowser) > 0 {
		SyncOpenBrowserActions(c, codeActions.OpenBrowser)
	}

	// Sync open learn lesson actions
	if len(codeActions.OpenLearnLesson) > 0 {
		SyncLearnLessonActions(c, codeActions.OpenLearnLesson)
	}

	// Sync SCA upgrade actions
	if len(codeActions.ScaUpgrade) > 0 {
		SyncCodeActionGroup(c, "scaUpgrade", codeActions.ScaUpgrade)
	}
}

// SyncOpenBrowserActions syncs open browser code actions from LDX-Sync configuration
func SyncOpenBrowserActions(c *config.Config, actions []ldx_sync_config.CodeAction) {
	// Find the action for the current integration or use the first enabled one
	var enabledAction *ldx_sync_config.CodeAction
	for _, action := range actions {
		if action.Enabled != nil && *action.Enabled {
			enabledAction = &action
			break
		}
	}

	if enabledAction != nil {
		oldBrowserActions := c.IsSnykOpenBrowserActionEnabled()
		if oldBrowserActions != *enabledAction.Enabled {
			c.SetSnykOpenBrowserActionsEnabled(*enabledAction.Enabled)
			c.Logger().Info().
				Bool("browserActionsEnabled", *enabledAction.Enabled).
				Str("integrationName", getStringValue(enabledAction.IntegrationName)).
				Msg("Open browser actions updated from LDX-Sync")
		}
	}
}

// SyncLearnLessonActions syncs learn lesson code actions from LDX-Sync configuration
func SyncLearnLessonActions(c *config.Config, actions []ldx_sync_config.CodeAction) {
	// Find the action for the current integration or use the first enabled one
	var enabledAction *ldx_sync_config.CodeAction
	for _, action := range actions {
		if action.Enabled != nil && *action.Enabled {
			enabledAction = &action
			break
		}
	}

	if enabledAction != nil {
		oldLearnActions := c.IsSnykLearnCodeActionsEnabled()
		if oldLearnActions != *enabledAction.Enabled {
			c.SetSnykLearnCodeActionsEnabled(*enabledAction.Enabled)
			c.Logger().Info().
				Bool("learnActionsEnabled", *enabledAction.Enabled).
				Str("integrationName", getStringValue(enabledAction.IntegrationName)).
				Msg("Learn lesson actions updated from LDX-Sync")
		}
	}
}

// SyncCodeActionGroup syncs a group of code actions from LDX-Sync configuration
func SyncCodeActionGroup(c *config.Config, actionType string, actions []ldx_sync_config.CodeAction) {
	c.Logger().Debug().Int("actionCount", len(actions)).Str("actionType", actionType).Msg("Code actions available from LDX-Sync")

	for i, action := range actions {
		c.Logger().Debug().
			Int("actionIndex", i).
			Str("actionType", actionType).
			Bool("enabled", action.Enabled != nil && *action.Enabled).
			Str("integrationName", getStringValue(action.IntegrationName)).
			Msg("Code action details from LDX-Sync")
	}
}

// SyncHoverVerbosity syncs hover verbosity from LDX-Sync configuration
func SyncHoverVerbosity(c *config.Config, verbosity int) {
	oldVerbosity := c.HoverVerbosity()
	if oldVerbosity != verbosity {
		c.SetHoverVerbosity(verbosity)
		c.Logger().Info().Int("hoverVerbosity", verbosity).Msg("Hover verbosity updated from LDX-Sync")
	}
}

// SyncIssueViewConfig syncs issue view configuration from LDX-Sync configuration
func SyncIssueViewConfig(c *config.Config, ivConfig *ldx_sync_config.IssueViewConfig) {
	// Sync issue view options if available
	if ivConfig.IgnoredIssues != nil || ivConfig.OpenIssues != nil {
		oldOptions := c.IssueViewOptions()
		newOptions := types.IssueViewOptions{
			OpenIssues:    getBoolValue(ivConfig.OpenIssues, oldOptions.OpenIssues),
			IgnoredIssues: getBoolValue(ivConfig.IgnoredIssues, oldOptions.IgnoredIssues),
		}

		if !reflect.DeepEqual(oldOptions, newOptions) {
			c.SetIssueViewOptions(&newOptions)
			c.Logger().Info().
				Bool("openIssues", newOptions.OpenIssues).
				Bool("ignoredIssues", newOptions.IgnoredIssues).
				Msg("Issue view options updated from LDX-Sync")
		}
	}
}

// SyncCompleteScanConfig syncs complete scan configuration from LDX-Sync configuration
func SyncCompleteScanConfig(c *config.Config, scanConfig *ldx_sync_config.ScanConfig) {
	// Sync automatic scanning
	if scanConfig.Automatic != nil {
		SyncScanConfig(c, *scanConfig.Automatic)
	}

	// Log net new scanning setting
	if scanConfig.NetNew != nil {
		c.Logger().Debug().Bool("netNew", *scanConfig.NetNew).Msg("Net new scanning setting available from LDX-Sync")
	}
}

// SyncCompleteTrustConfig syncs complete trust configuration from LDX-Sync configuration
func SyncCompleteTrustConfig(c *config.Config, trustConfig *ldx_sync_config.TrustConfig) {
	// Log trust enablement
	if trustConfig.Enable != nil {
		c.Logger().Debug().Bool("trustEnabled", *trustConfig.Enable).Msg("Trust configuration enablement available from LDX-Sync")
	}

	// Sync trusted folders
	if len(trustConfig.TrustedFolders) > 0 {
		SyncTrustConfig(c, trustConfig.TrustedFolders)
	}
}

// Helper function to safely get int value from pointer
func getIntValue(ptr *int) int {
	if ptr == nil {
		return 0
	}
	return *ptr
}

// Helper function to safely get string value from pointer
func getStringValue(ptr *string) string {
	if ptr == nil {
		return ""
	}
	return *ptr
}

// SyncFolderIntegrationInfo syncs integration information from folder configuration
func SyncFolderIntegrationInfo(c *config.Config, folderConfig ldx_sync_config.FolderConfig) {
	// Extract integration information from folder path or remote URL patterns
	// This is a simplified approach - in practice, you might want to parse the remote URL
	// or use other heuristics to determine the integration type

	// For now, we'll just log the information and could potentially sync integration name/version
	// if we can determine them from the folder configuration
	if folderConfig.RemoteUrl != "" {
		c.Logger().Debug().
			Str("remoteUrl", folderConfig.RemoteUrl).
			Str("folderPath", folderConfig.FolderPath).
			Msg("Folder integration context available from LDX-Sync")
	}
}

// Helper function to safely get boolean value from pointer with fallback
func getBoolValue(ptr *bool, fallback bool) bool {
	if ptr == nil {
		return fallback
	}
	return *ptr
}
