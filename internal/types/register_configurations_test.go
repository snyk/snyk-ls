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

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// All 31 settings from settingScopeRegistry for safety net coverage
var allSettings = []string{
	// Machine-scope (14)
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
	// Folder-scope (4)
	SettingReferenceFolder,
	SettingReferenceBranch,
	SettingAdditionalParameters,
	SettingAdditionalEnvironment,
}

// expectedAnnotations defines the expected annotations for each setting.
// scope, remoteKey, displayName, ideKey. Empty string means annotation may be absent or empty.
var expectedAnnotations = map[string]struct {
	scope       string
	remoteKey   string
	displayName string
	ideKey      string
}{
	// Machine-scope
	SettingApiEndpoint:                     {"machine", "api_endpoint", "API Endpoint", "endpoint"},
	SettingCodeEndpoint:                    {"machine", "code_endpoint", "Code API Endpoint", "snykCodeApi"},
	SettingAuthenticationMethod:            {"machine", "authentication_method", "Authentication Method", "authenticationMethod"},
	SettingProxyHttp:                       {"machine", "proxy_http", "Proxy HTTP", "proxyHttp"},
	SettingProxyHttps:                      {"machine", "proxy_https", "Proxy HTTPS", "proxyHttps"},
	SettingProxyNoProxy:                    {"machine", "proxy_no_proxy", "Proxy No Proxy", "proxyNoProxy"},
	SettingProxyInsecure:                   {"machine", "proxy_insecure", "Proxy Insecure", "insecure"},
	SettingAutoConfigureMcpServer:          {"machine", "auto_configure_mcp_server", "Auto Configure MCP Server", "autoConfigureSnykMcpServer"},
	SettingPublishSecurityAtInceptionRules: {"machine", "publish_security_at_inception_rules", "Publish Security At Inception Rules", "publishSecurityAtInceptionRules"},
	SettingTrustEnabled:                    {"machine", "trust_enabled", "Trust Enabled", "enableTrustedFoldersFeature"},
	SettingBinaryBaseUrl:                   {"machine", "binary_base_url", "Binary Base URL", "cliBaseDownloadURL"},
	SettingCliPath:                         {"machine", "cli_path", "CLI Path", "cliPath"},
	SettingAutomaticDownload:               {"machine", "automatic_download", "Automatic Download", "manageBinariesAutomatically"},
	SettingCliReleaseChannel:               {"machine", "cli_release_channel", "CLI Release Channel", "cliReleaseChannel"},
	// Org-scope
	SettingEnabledSeverities:      {"org", "severities", "Enabled Severities", "filterSeverity"},
	SettingRiskScoreThreshold:     {"org", "risk_score_threshold", "Risk Score Threshold", "riskScoreThreshold"},
	SettingCweIds:                 {"org", "cwe", "CWE IDs", ""},
	SettingCveIds:                 {"org", "cve", "CVE IDs", ""},
	SettingRuleIds:                {"org", "rule", "Rule IDs", ""},
	SettingSnykCodeEnabled:        {"org", "", "Snyk Code Enabled", "activateSnykCode"},
	SettingSnykOssEnabled:         {"org", "", "Snyk OSS Enabled", "activateSnykOpenSource"},
	SettingSnykIacEnabled:         {"org", "", "Snyk IaC Enabled", "activateSnykIac"},
	SettingSnykSecretsEnabled:     {"org", "", "Snyk Secrets Enabled", "activateSnykSecrets"},
	SettingScanAutomatic:          {"org", "automatic", "Scan Automatic", "scanningMode"},
	SettingScanNetNew:             {"org", "net_new", "Scan Net New", "enableDeltaFindings"},
	SettingIssueViewOpenIssues:    {"org", "open_issues", "Issue View Open Issues", ""},
	SettingIssueViewIgnoredIssues: {"org", "ignored_issues", "Issue View Ignored Issues", ""},
	// Folder-scope
	SettingReferenceFolder:       {"folder", "reference_folder", "Reference Folder", ""},
	SettingReferenceBranch:       {"folder", "reference_branch", "Reference Branch", ""},
	SettingAdditionalParameters:  {"folder", "additional_parameters", "Additional Parameters", "additionalParams"},
	SettingAdditionalEnvironment: {"folder", "additional_environment", "Additional Environment", "additionalEnv"},
}

// TestRegisterAllConfigurations_FC048_ProducesFlagsWithCorrectAnnotations verifies that
// RegisterAllConfigurations produces all expected flags with correct annotations.
func TestRegisterAllConfigurations_FC048_ProducesFlagsWithCorrectAnnotations(t *testing.T) {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterAllConfigurations(fs)

	// Verify all 31 settings have flags
	assert.Len(t, allSettings, 31, "allSettings should have 31 entries")

	for _, name := range allSettings {
		t.Run(name, func(t *testing.T) {
			flag := fs.Lookup(name)
			require.NotNil(t, flag, "flag %q should exist", name)

			expected := expectedAnnotations[name]
			require.NotEmpty(t, expected.scope, "test data for %q missing scope", name)

			// Verify scope
			scopeVals, ok := flag.Annotations[configuration.AnnotationScope]
			require.True(t, ok, "flag %q should have config.scope annotation", name)
			require.Len(t, scopeVals, 1, "flag %q scope should have exactly one value", name)
			assert.Equal(t, expected.scope, scopeVals[0], "flag %q scope mismatch", name)

			// Verify remoteKey (may be empty for product settings)
			if expected.remoteKey != "" {
				remoteVals, hasRemote := flag.Annotations[configuration.AnnotationRemoteKey]
				require.True(t, hasRemote, "flag %q should have config.remoteKey when expected", name)
				require.Len(t, remoteVals, 1)
				assert.Equal(t, expected.remoteKey, remoteVals[0], "flag %q remoteKey mismatch", name)
			}

			// Verify displayName
			displayVals, ok := flag.Annotations[configuration.AnnotationDisplayName]
			require.True(t, ok, "flag %q should have config.displayName annotation", name)
			require.Len(t, displayVals, 1)
			assert.Equal(t, expected.displayName, displayVals[0], "flag %q displayName mismatch", name)

			// Verify ideKey (may be empty)
			if expected.ideKey != "" {
				ideVals, ok := flag.Annotations[configuration.AnnotationIdeKey]
				require.True(t, ok, "flag %q should have config.ideKey when expected", name)
				require.Len(t, ideVals, 1)
				assert.Equal(t, expected.ideKey, ideVals[0], "flag %q ideKey mismatch", name)
			}
		})
	}
}

// TestRegisterAllConfigurations_SettingScopeRegistryCoverage ensures every entry in
// settingScopeRegistry has a corresponding flag with matching scope annotation.
func TestRegisterAllConfigurations_SettingScopeRegistryCoverage(t *testing.T) {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterAllConfigurations(fs)

	for _, settingName := range allSettings {
		expectedScope := GetSettingScope(settingName)
		expectedScopeStr := expectedScope.String()

		flag := fs.Lookup(settingName)
		require.NotNil(t, flag, "setting %q from registry must have a registered flag", settingName)

		scopeVals, ok := flag.Annotations[configuration.AnnotationScope]
		require.True(t, ok, "flag for %q must have scope annotation", settingName)
		require.Len(t, scopeVals, 1)
		assert.Equal(t, expectedScopeStr, scopeVals[0],
			"flag %q scope annotation must match settingScopeRegistry", settingName)
	}
}
