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
	SettingCliInsecure,
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
	SettingApiEndpoint:                     {"machine", "api_endpoint", "API Endpoint", "endpoint", false},
	SettingCodeEndpoint:                    {"machine", "code_endpoint", "Code API Endpoint", "snykCodeApi", false},
	SettingAuthenticationMethod:            {"machine", "authentication_method", "Authentication Method", "authenticationMethod", false},
	SettingProxyHttp:                       {"machine", "proxy_http", "Proxy HTTP", "proxyHttp", false},
	SettingProxyHttps:                      {"machine", "proxy_https", "Proxy HTTPS", "proxyHttps", false},
	SettingProxyNoProxy:                    {"machine", "proxy_no_proxy", "Proxy No Proxy", "proxyNoProxy", false},
	SettingProxyInsecure:                   {"machine", "proxy_insecure", "Proxy Insecure", "insecure", false},
	SettingAutoConfigureMcpServer:          {"machine", "auto_configure_mcp_server", "Auto Configure MCP Server", "autoConfigureSnykMcpServer", false},
	SettingPublishSecurityAtInceptionRules: {"machine", "publish_security_at_inception_rules", "Publish Security At Inception Rules", "publishSecurityAtInceptionRules", false},
	SettingTrustEnabled:                    {"machine", "trust_enabled", "Trust Enabled", "enableTrustedFoldersFeature", false},
	SettingBinaryBaseUrl:                   {"machine", "binary_base_url", "Binary Base URL", "cliBaseDownloadURL", false},
	SettingCliPath:                         {"machine", "cli_path", "CLI Path", "cliPath", false},
	SettingAutomaticDownload:               {"machine", "automatic_download", "Automatic Download", "manageBinariesAutomatically", false},
	SettingCliReleaseChannel:               {"machine", "cli_release_channel", "CLI Release Channel", "cliReleaseChannel", false},
	// Org-scope
	SettingEnabledSeverities:      {"org", "severities", "Enabled Severities", "filterSeverity", false},
	SettingRiskScoreThreshold:     {"org", "risk_score_threshold", "Risk Score Threshold", "riskScoreThreshold", false},
	SettingCweIds:                 {"org", "cwe", "CWE IDs", "", false},
	SettingCveIds:                 {"org", "cve", "CVE IDs", "", false},
	SettingRuleIds:                {"org", "rule", "Rule IDs", "", false},
	SettingSnykCodeEnabled:        {"org", "", "Snyk Code Enabled", "activateSnykCode", false},
	SettingSnykOssEnabled:         {"org", "", "Snyk OSS Enabled", "activateSnykOpenSource", false},
	SettingSnykIacEnabled:         {"org", "", "Snyk IaC Enabled", "activateSnykIac", false},
	SettingSnykSecretsEnabled:     {"org", "", "Snyk Secrets Enabled", "activateSnykSecrets", false},
	SettingScanAutomatic:          {"org", "automatic", "Scan Automatic", "scanningMode", false},
	SettingScanNetNew:             {"org", "net_new", "Scan Net New", "enableDeltaFindings", false},
	SettingIssueViewOpenIssues:    {"org", "open_issues", "Issue View Open Issues", "", false},
	SettingIssueViewIgnoredIssues: {"org", "ignored_issues", "Issue View Ignored Issues", "", false},
	// Folder-scope
	SettingReferenceFolder:            {"folder", "reference_folder", "Reference Folder", "", false},
	SettingReferenceBranch:            {"folder", "reference_branch", "Reference Branch", "", false},
	SettingAdditionalParameters:       {"folder", "additional_parameters", "Additional Parameters", "additionalParams", false},
	SettingCliAdditionalOssParameters: {"folder", "", "CLI Additional OSS Parameters", "", false},
	SettingAdditionalEnvironment:      {"folder", "additional_environment", "Additional Environment", "additionalEnv", false},
	SettingBaseBranch:                 {"folder", "", "Base Branch", "baseBranch", false},
	SettingLocalBranches:              {"folder", "", "Local Branches", "", false},
	SettingPreferredOrg:               {"folder", "", "Preferred Organization", "preferredOrg", false},
	SettingAutoDeterminedOrg:          {"folder", "", "Auto-Determined Organization", "", false},
	SettingOrgSetByUser:               {"folder", "", "Organization Set By User", "orgSetByUser", false},
	SettingScanCommandConfig:          {"folder", "", "Scan Command Config", "scanCommandConfig", false},
	SettingSastSettings:               {"folder", "", "SAST Settings", "", false},
	// Machine-scope (continued)
	SettingOrganization:                   {"machine", "", "Organization", "organization", false},
	SettingAutomaticAuthentication:        {"machine", "", "Automatic Authentication", "automaticAuthentication", false},
	SettingCliInsecure:                    {"machine", "", "CLI Insecure", "insecure", false},
	SettingFormat:                         {"machine", "", "Output Format", "", false},
	SettingDeviceId:                       {"machine", "", "Device ID", "", false},
	SettingOffline:                        {"machine", "", "Offline Mode", "", false},
	SettingUserSettingsPath:               {"machine", "", "User Settings Path", "", false},
	SettingHoverVerbosity:                 {"machine", "", "Hover Verbosity", "", false},
	SettingClientProtocolVersion:          {"machine", "", "Client Protocol Version", "", false},
	SettingOsPlatform:                     {"machine", "", "OS Platform", "", false},
	SettingOsArch:                         {"machine", "", "OS Architecture", "", false},
	SettingRuntimeName:                    {"machine", "", "Runtime Name", "", false},
	SettingRuntimeVersion:                 {"machine", "", "Runtime Version", "", false},
	SettingTrustedFolders:                 {"machine", "", "Trusted Folders", "", false},
	SettingSecureAtInceptionExecutionFreq: {"machine", "", "Secure At Inception Frequency", "", false},
	// Write-only (machine-scope)
	SettingToken:                        {"machine", "", "Token", "token", true},
	SettingSendErrorReports:             {"machine", "", "Send Error Reports", "sendErrorReports", true},
	SettingEnableSnykLearnCodeActions:   {"machine", "", "Snyk Learn Code Actions", "enableSnykLearnCodeActions", true},
	SettingEnableSnykOssQuickFixActions: {"machine", "", "Snyk OSS Quick Fix Code Actions", "enableSnykOSSQuickFixCodeActions", true},
	SettingEnableSnykOpenBrowserActions: {"machine", "", "Snyk Open Browser Actions", "enableSnykOpenBrowserActions", true},
}

// TestRegisterAllConfigurations_FC048_ProducesFlagsWithCorrectAnnotations verifies that
// RegisterAllConfigurations produces all expected flags with correct annotations.
func TestRegisterAllConfigurations_FC048_ProducesFlagsWithCorrectAnnotations(t *testing.T) {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterAllConfigurations(fs)

	assert.Len(t, allSettings, 59, "allSettings should have 59 entries (29 machine + 5 write-only + 13 org + 12 folder)")

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

			// Verify ideKey (may be empty)
			if expected.ideKey != "" {
				ideVals, ok := flag.Annotations[configresolver.AnnotationIdeKey]
				require.True(t, ok, "flag %q should have config.ideKey when expected", name)
				require.Len(t, ideVals, 1)
				assert.Equal(t, expected.ideKey, ideVals[0], "flag %q ideKey mismatch", name)
			}

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
// settingScopeRegistry has a corresponding flag with matching scope annotation.
func TestRegisterAllConfigurations_SettingScopeRegistryCoverage(t *testing.T) {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterAllConfigurations(fs)

	for settingName, expectedScope := range settingScopeRegistry {
		t.Run(settingName, func(t *testing.T) {
			expectedScopeStr := expectedScope.String()

			flag := fs.Lookup(settingName)
			require.NotNil(t, flag, "setting %q from registry must have a registered flag", settingName)

			scopeVals, ok := flag.Annotations[configresolver.AnnotationScope]
			require.True(t, ok, "flag for %q must have scope annotation", settingName)
			require.Len(t, scopeVals, 1)
			assert.Equal(t, expectedScopeStr, scopeVals[0],
				"flag %q scope annotation must match settingScopeRegistry", settingName)
		})
	}
}
