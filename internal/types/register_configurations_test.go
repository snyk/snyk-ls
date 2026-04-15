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
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// All 59 registered settings: 29 machine + 5 write-only + 13 org + 12 folder
var allSettings = []string{
	// Machine-scope
	SettingApiEndpoint,
	SettingCodeEndpoint,
	SettingAuthenticationMethod,
	SettingProxyHttp,
	SettingProxyHttps,
	SettingProxyNoProxy,
	SettingProxyInsecure,
	SettingAutoConfigureMcpServer,
	SettingPublishSecurityAtInceptionRules,
	SettingTrustEnabled,
	SettingBinaryBaseUrl,
	SettingCliPath,
	SettingAutomaticDownload,
	SettingCliReleaseChannel,
	SettingOrganization,
	SettingAutomaticAuthentication,

	SettingFormat,
	SettingDeviceId,
	SettingOffline,
	SettingUserSettingsPath,
	SettingHoverVerbosity,
	SettingClientProtocolVersion,
	SettingOsPlatform,
	SettingOsArch,
	SettingRuntimeName,
	SettingRuntimeVersion,
	SettingTrustedFolders,
	SettingSecureAtInceptionExecutionFreq,
	SettingToken,
	SettingSendErrorReports,
	SettingEnableSnykLearnCodeActions,
	SettingEnableSnykOssQuickFixActions,
	SettingEnableSnykOpenBrowserActions,
	// Org-scope (13)
	SettingEnabledSeverities,
	SettingRiskScoreThreshold,
	SettingCweIds,
	SettingCveIds,
	SettingRuleIds,
	SettingSnykCodeEnabled,
	SettingSnykOssEnabled,
	SettingSnykIacEnabled,
	SettingSnykSecretsEnabled,
	SettingScanAutomatic,
	SettingScanNetNew,
	SettingIssueViewOpenIssues,
	SettingIssueViewIgnoredIssues,
	// Folder-scope (12)
	SettingReferenceFolder,
	SettingReferenceBranch,
	SettingAdditionalParameters,
	SettingCliAdditionalOssParameters,
	SettingAdditionalEnvironment,
	SettingBaseBranch,
	SettingLocalBranches,
	SettingPreferredOrg,
	SettingAutoDeterminedOrg,
	SettingOrgSetByUser,
	SettingScanCommandConfig,
	SettingSastSettings,
}

var machineScope = string(configresolver.MachineScope)
var folderScope = string(configresolver.FolderScope)

// expectedAnnotations defines the expected annotations for each setting.
// scope, remoteKey, displayName, ideKey, writeOnly. Empty string means annotation may be absent or empty.
var expectedAnnotations = map[string]struct {
	scope       string
	remoteKey   string
	displayName string
	ideKey      string
	writeOnly   bool
}{
	// Machine-scope
	SettingApiEndpoint:                     {machineScope, "api_endpoint", "API Endpoint", "endpoint", false},
	SettingCodeEndpoint:                    {machineScope, "code_endpoint", "Code API Endpoint", "snykCodeApi", false},
	SettingAuthenticationMethod:            {machineScope, "authentication_method", "Authentication Method", "authenticationMethod", false},
	SettingProxyHttp:                       {machineScope, "proxy_http", "Proxy HTTP", "proxyHttp", false},
	SettingProxyHttps:                      {machineScope, "proxy_https", "Proxy HTTPS", "proxyHttps", false},
	SettingProxyNoProxy:                    {machineScope, "proxy_no_proxy", "Proxy No Proxy", "proxyNoProxy", false},
	SettingProxyInsecure:                   {machineScope, "proxy_insecure", "Proxy Insecure", "insecure", false},
	SettingAutoConfigureMcpServer:          {machineScope, "auto_configure_mcp_server", "Auto Configure MCP Server", "autoConfigureSnykMcpServer", false},
	SettingPublishSecurityAtInceptionRules: {machineScope, "publish_security_at_inception_rules", "Publish Security At Inception Rules", "publishSecurityAtInceptionRules", false},
	SettingTrustEnabled:                    {machineScope, "trust_enabled", "Trust Enabled", "enableTrustedFoldersFeature", false},
	SettingBinaryBaseUrl:                   {machineScope, "binary_base_url", "Binary Base URL", "cliBaseDownloadURL", false},
	SettingCliPath:                         {machineScope, "cli_path", "CLI Path", "cliPath", false},
	SettingAutomaticDownload:               {machineScope, "automatic_download", "Automatic Download", "manageBinariesAutomatically", false},
	SettingCliReleaseChannel:               {machineScope, "cli_release_channel", "CLI Release Channel", "cliReleaseChannel", false},
	// Org-scope
	SettingEnabledSeverities:      {folderScope, "severities", "Enabled Severities", "filterSeverity", false},
	SettingRiskScoreThreshold:     {folderScope, "risk_score_threshold", "Risk Score Threshold", "riskScoreThreshold", false},
	SettingCweIds:                 {folderScope, "cwe", "CWE IDs", "", false},
	SettingCveIds:                 {folderScope, "cve", "CVE IDs", "", false},
	SettingRuleIds:                {folderScope, "rule", "Rule IDs", "", false},
	SettingSnykCodeEnabled:        {folderScope, "", "Snyk Code Enabled", "activateSnykCode", false},
	SettingSnykOssEnabled:         {folderScope, "", "Snyk OSS Enabled", "activateSnykOpenSource", false},
	SettingSnykIacEnabled:         {folderScope, "", "Snyk IaC Enabled", "activateSnykIac", false},
	SettingSnykSecretsEnabled:     {folderScope, "", "Snyk Secrets Enabled", "activateSnykSecrets", false},
	SettingScanAutomatic:          {folderScope, "automatic", "Scan Automatic", "scanningMode", false},
	SettingScanNetNew:             {folderScope, "net_new", "Scan Net New", "enableDeltaFindings", false},
	SettingIssueViewOpenIssues:    {folderScope, "open_issues", "Issue View Open Issues", "", false},
	SettingIssueViewIgnoredIssues: {folderScope, "ignored_issues", "Issue View Ignored Issues", "", false},
	// Folder-scope
	SettingReferenceFolder:            {folderScope, "reference_folder", "Reference Folder", "", false},
	SettingReferenceBranch:            {folderScope, "reference_branch", "Reference Branch", "", false},
	SettingAdditionalParameters:       {folderScope, "additional_parameters", "Additional Parameters", "additionalParams", false},
	SettingCliAdditionalOssParameters: {folderScope, "", "CLI Additional OSS Parameters", "", false},
	SettingAdditionalEnvironment:      {folderScope, "additional_environment", "Additional Environment", "additionalEnv", false},
	SettingBaseBranch:                 {folderScope, "", "Base Branch", "baseBranch", false},
	SettingLocalBranches:              {folderScope, "", "Local Branches", "", false},
	SettingPreferredOrg:               {folderScope, "", "Preferred Organization", "preferredOrg", false},
	SettingAutoDeterminedOrg:          {folderScope, "", "Auto-Determined Organization", "", false},
	SettingOrgSetByUser:               {folderScope, "", "Organization Set By User", "orgSetByUser", false},
	SettingScanCommandConfig:          {folderScope, "", "Scan Command Config", "scanCommandConfig", false},
	SettingSastSettings:               {folderScope, "", "SAST Settings", "", false},
	// Machine-scope (continued)
	SettingOrganization:            {machineScope, "", "Organization", "organization", false},
	SettingAutomaticAuthentication: {machineScope, "", "Automatic Authentication", "automaticAuthentication", false},

	SettingFormat:                         {machineScope, "", "Output Format", "", false},
	SettingDeviceId:                       {machineScope, "", "Device ID", "", false},
	SettingOffline:                        {machineScope, "", "Offline Mode", "", false},
	SettingUserSettingsPath:               {machineScope, "", "User Settings Path", "", false},
	SettingHoverVerbosity:                 {machineScope, "", "Hover Verbosity", "", false},
	SettingClientProtocolVersion:          {machineScope, "", "Client Protocol Version", "", false},
	SettingOsPlatform:                     {machineScope, "", "OS Platform", "", false},
	SettingOsArch:                         {machineScope, "", "OS Architecture", "", false},
	SettingRuntimeName:                    {machineScope, "", "Runtime Name", "", false},
	SettingRuntimeVersion:                 {machineScope, "", "Runtime Version", "", false},
	SettingTrustedFolders:                 {machineScope, "", "Trusted Folders", "", false},
	SettingSecureAtInceptionExecutionFreq: {machineScope, "", "Secure At Inception Frequency", "", false},
	// Write-only (machine-scope)
	SettingToken:                        {machineScope, "", "Token", "token", true},
	SettingSendErrorReports:             {machineScope, "", "Send Error Reports", "sendErrorReports", true},
	SettingEnableSnykLearnCodeActions:   {machineScope, "", "Snyk Learn Code Actions", "enableSnykLearnCodeActions", true},
	SettingEnableSnykOssQuickFixActions: {machineScope, "", "Snyk OSS Quick Fix Code Actions", "enableSnykOSSQuickFixCodeActions", true},
	SettingEnableSnykOpenBrowserActions: {machineScope, "", "Snyk Open Browser Actions", "enableSnykOpenBrowserActions", true},
}

// TestRegisterAllConfigurations_FC048_ProducesFlagsWithCorrectAnnotations verifies that
// RegisterAllConfigurations produces all expected flags with correct annotations.
func TestRegisterAllConfigurations_FC048_ProducesFlagsWithCorrectAnnotations(t *testing.T) {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterAllConfigurations(fs)

	assert.Len(t, allSettings, 58, "allSettings should have 58 entries (28 machine + 5 write-only + 13 org + 12 folder)")

	for _, name := range allSettings {
		t.Run(name, func(t *testing.T) {
			flag := fs.Lookup(name)
			require.NotNil(t, flag, "flag %q should exist", name)

			expected := expectedAnnotations[name]
			require.NotEmpty(t, expected.scope, "test data for %q missing scope", name)

			// Verify scope
			scopeVals, ok := flag.Annotations[configresolver.AnnotationScope]
			require.True(t, ok, "flag %q should have config.scope annotation", name)
			require.Len(t, scopeVals, 1, "flag %q scope should have exactly one value", name)
			assert.Equal(t, expected.scope, scopeVals[0], "flag %q scope mismatch", name)

			// Verify remoteKey (may be empty for product settings)
			if expected.remoteKey != "" {
				remoteVals, hasRemote := flag.Annotations[configresolver.AnnotationRemoteKey]
				require.True(t, hasRemote, "flag %q should have config.remoteKey when expected", name)
				require.Len(t, remoteVals, 1)
				assert.Equal(t, expected.remoteKey, remoteVals[0], "flag %q remoteKey mismatch", name)
			}

			// Verify displayName
			displayVals, ok := flag.Annotations[configresolver.AnnotationDisplayName]
			require.True(t, ok, "flag %q should have config.displayName annotation", name)
			require.Len(t, displayVals, 1)
			assert.Equal(t, expected.displayName, displayVals[0], "flag %q displayName mismatch", name)

			// Verify writeOnly annotation (only for write-only settings)
			if expected.writeOnly {
				writeOnlyVals, ok := flag.Annotations[configresolver.AnnotationWriteOnly]
				require.True(t, ok, "flag %q should have config.writeOnly annotation", name)
				require.Len(t, writeOnlyVals, 1)
				assert.Equal(t, "true", writeOnlyVals[0], "flag %q writeOnly should be 'true'", name)
			}
		})
	}
}

// writeOnlySettingsForTest are settings that are accepted IDE→LS but NOT sent LS→IDE (for test use)
var writeOnlySettingsForTest = []string{
	SettingToken,
	SettingSendErrorReports,
	SettingEnableSnykLearnCodeActions,
	SettingEnableSnykOssQuickFixActions,
	SettingEnableSnykOpenBrowserActions,
}

// TestRegisterAllConfigurations_WriteOnlySettings verifies that write-only settings
// have the config.writeOnly annotation.
func TestRegisterAllConfigurations_WriteOnlySettings(t *testing.T) {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterAllConfigurations(fs)

	for _, name := range writeOnlySettingsForTest {
		t.Run(name, func(t *testing.T) {
			flag := fs.Lookup(name)
			require.NotNil(t, flag, "flag %q should exist", name)
			writeOnlyVals, ok := flag.Annotations[configresolver.AnnotationWriteOnly]
			require.True(t, ok, "flag %q should have config.writeOnly annotation", name)
			require.Len(t, writeOnlyVals, 1)
			assert.Equal(t, "true", writeOnlyVals[0], "flag %q writeOnly annotation should be 'true'", name)
		})
	}
}

// TestRegisterAllConfigurations_SettingScopeRegistryCoverage ensures every entry in
// TestRegisterAllConfigurations_AllFlagsHaveScopeAnnotation verifies every registered flag
// has a valid scope annotation (either machine or folder).
func TestRegisterAllConfigurations_AllFlagsHaveScopeAnnotation(t *testing.T) {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterAllConfigurations(fs)
	fm := workflow.ConfigurationOptionsFromFlagset(fs)

	fs.VisitAll(func(f *pflag.Flag) {
		t.Run(f.Name, func(t *testing.T) {
			scope := GetSettingScope(fm, f.Name)
			require.True(t,
				scope == configresolver.MachineScope || scope == configresolver.FolderScope,
				"flag %q has unexpected scope %q", f.Name, scope)
		})
	})
}

func fmFromFlags(t *testing.T) workflow.ConfigurationOptionsMetaData {
	t.Helper()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterAllConfigurations(fs)
	return workflow.ConfigurationOptionsFromFlagset(fs)
}

func TestGetSettingScope_MachineScope(t *testing.T) {
	fm := fmFromFlags(t)
	machineSettings := []string{
		SettingApiEndpoint, SettingCliPath, SettingToken,
		SettingAutomaticDownload, SettingOrganization,
	}
	for _, name := range machineSettings {
		assert.Equal(t, configresolver.MachineScope, GetSettingScope(fm, name), "expected %q to be MachineScope", name)
	}
}

func TestGetSettingScope_FolderScope(t *testing.T) {
	fm := fmFromFlags(t)
	// formerly org-scoped and folder-scoped settings both map to FolderScope now
	folderSettings := []string{
		SettingSnykCodeEnabled, SettingScanAutomatic, SettingEnabledSeverities,
		SettingBaseBranch, SettingReferenceFolder, SettingPreferredOrg,
	}
	for _, name := range folderSettings {
		assert.Equal(t, configresolver.FolderScope, GetSettingScope(fm, name), "expected %q to be FolderScope", name)
	}
}

func TestGetSettingScope_DefaultsFolderScope(t *testing.T) {
	fm := fmFromFlags(t)
	assert.Equal(t, configresolver.FolderScope, GetSettingScope(fm, "unknown_setting_xyz"))
}

func TestGetSettingScope_NilFmDefaultsFolderScope(t *testing.T) {
	assert.Equal(t, configresolver.FolderScope, GetSettingScope(nil, SettingApiEndpoint))
}

func TestIsMachineWideSetting(t *testing.T) {
	fm := fmFromFlags(t)
	assert.True(t, IsMachineWideSetting(fm, SettingCliPath))
	assert.False(t, IsMachineWideSetting(fm, SettingSnykCodeEnabled))
	assert.False(t, IsMachineWideSetting(fm, SettingBaseBranch))
}

func TestIsFolderScopedSetting(t *testing.T) {
	fm := fmFromFlags(t)
	assert.True(t, IsFolderScopedSetting(fm, SettingSnykCodeEnabled))
	assert.True(t, IsFolderScopedSetting(fm, SettingBaseBranch))
	assert.False(t, IsFolderScopedSetting(fm, SettingCliPath))
}

func TestIsWriteOnlySetting(t *testing.T) {
	fm := fmFromFlags(t)
	for _, name := range []string{
		SettingToken, SettingSendErrorReports,
		SettingEnableSnykLearnCodeActions, SettingEnableSnykOssQuickFixActions,
		SettingEnableSnykOpenBrowserActions,
	} {
		assert.True(t, IsWriteOnlySetting(fm, name), "expected %q to be write-only", name)
	}
	assert.False(t, IsWriteOnlySetting(fm, SettingSnykCodeEnabled))
	assert.False(t, IsWriteOnlySetting(nil, SettingToken))
}
