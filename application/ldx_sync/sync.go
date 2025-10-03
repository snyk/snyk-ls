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

	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config/ldx_sync/2024-10-15"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
)

// SyncConfiguration syncs LDX-Sync configuration to the Language Server configuration
func SyncConfiguration(c *config.Config) {
	c.Logger().Debug().Msg("Syncing LDX-Sync configuration")

	// Get the LDX-Sync configuration from the engine
	ldxConfig := c.Engine().GetConfiguration().Get("internal_ldx_sync_config")
	if ldxConfig == nil {
		c.Logger().Debug().Msg("No LDX-Sync configuration available")
		return
	}

	// Cast to the proper type - now using the raw API response
	config, ok := ldxConfig.(*v20241015.ConfigResponse)
	if !ok {
		c.Logger().Warn().Msg("Failed to cast LDX-Sync configuration to expected type")
		return
	}

	// Sync organization
	SyncOrganization(c, config)

	// Sync filter configuration
	SyncFilterConfig(c, config)

	// Sync IDE configuration
	SyncIdeConfig(c, config)

	// Sync proxy configuration
	SyncProxyConfig(c, config)

	c.Logger().Debug().Msg("LDX-Sync configuration sync completed")
}

// SyncOrganization syncs organization settings from LDX-Sync configuration
func SyncOrganization(c *config.Config, config *v20241015.ConfigResponse) {
	if config.Data.Attributes.ConfigData.Organizations == nil || len(*config.Data.Attributes.ConfigData.Organizations) == 0 {
		return
	}

	// Find the default organization or use the first one
	var selectedOrg *v20241015.Organization
	for _, org := range *config.Data.Attributes.ConfigData.Organizations {
		if org.IsDefault != nil && *org.IsDefault {
			selectedOrg = &org
			break
		}
	}

	if selectedOrg == nil {
		selectedOrg = &(*config.Data.Attributes.ConfigData.Organizations)[0]
	}

	if selectedOrg != nil {
		oldOrgId := c.Organization()
		c.SetOrganization(selectedOrg.Id)
		if oldOrgId != selectedOrg.Id {
			c.Logger().Info().Str("oldOrgId", oldOrgId).Str("newOrgId", selectedOrg.Id).Msg("Organization updated from LDX-Sync")
		}
	}
}

// SyncFilterConfig syncs filter configuration from LDX-Sync configuration
func SyncFilterConfig(c *config.Config, config *v20241015.ConfigResponse) {
	// Sync from FilterConfig.Severities if available
	if config.Data.Attributes.ConfigData.FilterConfig != nil && config.Data.Attributes.ConfigData.FilterConfig.Severities != nil {
		severities := config.Data.Attributes.ConfigData.FilterConfig.Severities
		oldFilter := c.FilterSeverity()
		newFilter := types.SeverityFilter{
			Critical: *severities.Critical,
			High:     *severities.High,
			Medium:   *severities.Medium,
			Low:      *severities.Low,
		}

		if !reflect.DeepEqual(oldFilter, newFilter) {
			c.SetSeverityFilter(&newFilter)
			c.Logger().Info().Interface("severityFilter", newFilter).Msg("Severity filter updated from LDX-Sync")
		}
	}
}

// SyncIdeConfig syncs IDE configuration from LDX-Sync configuration
func SyncIdeConfig(c *config.Config, config *v20241015.ConfigResponse) {
	// Sync product configuration from IdeConfig
	if config.Data.Attributes.ConfigData.IdeConfig != nil && config.Data.Attributes.ConfigData.IdeConfig.ProductConfig != nil {
		SyncProductConfig(c, config.Data.Attributes.ConfigData.IdeConfig.ProductConfig)
	}

	// Sync scan configuration from IdeConfig
	if config.Data.Attributes.ConfigData.IdeConfig != nil && config.Data.Attributes.ConfigData.IdeConfig.ScanConfig != nil {
		SyncScanConfig(c, config.Data.Attributes.ConfigData.IdeConfig.ScanConfig)
	}

	// Sync trust configuration from IdeConfig
	if config.Data.Attributes.ConfigData.IdeConfig != nil && config.Data.Attributes.ConfigData.IdeConfig.TrustConfig != nil {
		SyncTrustConfig(c, config.Data.Attributes.ConfigData.IdeConfig.TrustConfig)
	}
}

// SyncProductConfig syncs product configuration from LDX-Sync configuration
func SyncProductConfig(c *config.Config, productConfig *v20241015.ProductConfig) {
	// Sync individual product settings
	if productConfig.Code != nil {
		oldCodeEnabled := c.IsSnykCodeEnabled()
		if oldCodeEnabled != *productConfig.Code {
			c.SetSnykCodeEnabled(*productConfig.Code)
			c.Logger().Info().Bool("snykCodeEnabled", *productConfig.Code).Msg("Snyk Code enabled updated from LDX-Sync")
		}
	}

	if productConfig.Oss != nil {
		oldOssEnabled := c.IsSnykOssEnabled()
		if oldOssEnabled != *productConfig.Oss {
			c.SetSnykOssEnabled(*productConfig.Oss)
			c.Logger().Info().Bool("snykOssEnabled", *productConfig.Oss).Msg("Snyk OSS enabled updated from LDX-Sync")
		}
	}

	if productConfig.Iac != nil {
		oldIacEnabled := c.IsSnykIacEnabled()
		if oldIacEnabled != *productConfig.Iac {
			c.SetSnykIacEnabled(*productConfig.Iac)
			c.Logger().Info().Bool("snykIacEnabled", *productConfig.Iac).Msg("Snyk IaC enabled updated from LDX-Sync")
		}
	}
}

// SyncScanConfig syncs scan configuration from LDX-Sync configuration
func SyncScanConfig(c *config.Config, scanConfig *v20241015.ScanConfig) {
	if scanConfig.Automatic != nil {
		oldAutoScan := c.IsAutoScanEnabled()
		if oldAutoScan != *scanConfig.Automatic {
			c.SetAutomaticScanning(*scanConfig.Automatic)
			c.Logger().Info().Bool("automaticScanning", *scanConfig.Automatic).Msg("Automatic scanning updated from LDX-Sync")
		}
	}
}

// SyncTrustConfig syncs trust configuration from LDX-Sync configuration
func SyncTrustConfig(c *config.Config, trustConfig *v20241015.TrustConfig) {
	if trustConfig.TrustedFolders == nil {
		return
	}

	// Convert []string to []types.FilePath
	var filePaths []types.FilePath
	for _, folder := range *trustConfig.TrustedFolders {
		filePaths = append(filePaths, types.FilePath(folder))
	}

	oldTrustedFolders := c.TrustedFolders()
	if !reflect.DeepEqual(oldTrustedFolders, filePaths) {
		c.SetTrustedFolders(filePaths)
		c.Logger().Info().Interface("trustedFolders", filePaths).Msg("Trusted folders updated from LDX-Sync")
	}
}

// SyncProxyConfig syncs proxy configuration from LDX-Sync configuration
func SyncProxyConfig(c *config.Config, config *v20241015.ConfigResponse) {
	if config.Data.Attributes.ConfigData.ProxyConfig == nil {
		return
	}

	// Note: Proxy configuration methods are not available in the current Config interface
	// This is a placeholder for future implementation when proxy methods are added
	c.Logger().Debug().Interface("proxyConfig", config.Data.Attributes.ConfigData.ProxyConfig).Msg("Proxy configuration sync not yet implemented - methods not available in Config interface")
}
