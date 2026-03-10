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
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/spf13/pflag"
)

// RegisterAllConfigurations registers all snyk-ls configuration flags with their annotations
// into the given FlagSet. Flags are annotated with config.scope, config.remoteKey,
// config.displayName, config.description, and config.ideKey for framework integration.
func RegisterAllConfigurations(fs *pflag.FlagSet) {
	// Machine-scope settings (14)
	registerFlag(fs, SettingApiEndpoint, "", "API endpoint URL", map[string][]string{
		configuration.AnnotationScope:       {"machine"},
		configuration.AnnotationRemoteKey:   {"api_endpoint"},
		configuration.AnnotationDisplayName: {"API Endpoint"},
		configuration.AnnotationDescription: {"The Snyk API endpoint URL"},
		configuration.AnnotationIdeKey:      {"endpoint"},
	})
	registerFlag(fs, SettingCodeEndpoint, "", "Code API endpoint URL", map[string][]string{
		configuration.AnnotationScope:       {"machine"},
		configuration.AnnotationRemoteKey:   {"code_endpoint"},
		configuration.AnnotationDisplayName: {"Code API Endpoint"},
		configuration.AnnotationDescription: {"The Snyk Code API endpoint URL"},
		configuration.AnnotationIdeKey:      {"snykCodeApi"},
	})
	registerFlag(fs, SettingAuthenticationMethod, "", "Authentication method", map[string][]string{
		configuration.AnnotationScope:       {"machine"},
		configuration.AnnotationRemoteKey:   {"authentication_method"},
		configuration.AnnotationDisplayName: {"Authentication Method"},
		configuration.AnnotationDescription: {"Authentication method (token, oauth, pat)"},
		configuration.AnnotationIdeKey:      {"authenticationMethod"},
	})
	registerFlag(fs, SettingProxyHttp, "", "HTTP proxy URL", map[string][]string{
		configuration.AnnotationScope:       {"machine"},
		configuration.AnnotationRemoteKey:   {"proxy_http"},
		configuration.AnnotationDisplayName: {"Proxy HTTP"},
		configuration.AnnotationDescription: {"HTTP proxy URL"},
		configuration.AnnotationIdeKey:      {"proxyHttp"},
	})
	registerFlag(fs, SettingProxyHttps, "", "HTTPS proxy URL", map[string][]string{
		configuration.AnnotationScope:       {"machine"},
		configuration.AnnotationRemoteKey:   {"proxy_https"},
		configuration.AnnotationDisplayName: {"Proxy HTTPS"},
		configuration.AnnotationDescription: {"HTTPS proxy URL"},
		configuration.AnnotationIdeKey:      {"proxyHttps"},
	})
	registerFlag(fs, SettingProxyNoProxy, "", "No proxy list", map[string][]string{
		configuration.AnnotationScope:       {"machine"},
		configuration.AnnotationRemoteKey:   {"proxy_no_proxy"},
		configuration.AnnotationDisplayName: {"Proxy No Proxy"},
		configuration.AnnotationDescription: {"Comma-separated list of hosts to bypass proxy"},
		configuration.AnnotationIdeKey:      {"proxyNoProxy"},
	})
	registerFlag(fs, SettingProxyInsecure, "", "Allow insecure SSL connections", map[string][]string{
		configuration.AnnotationScope:       {"machine"},
		configuration.AnnotationRemoteKey:   {"proxy_insecure"},
		configuration.AnnotationDisplayName: {"Proxy Insecure"},
		configuration.AnnotationDescription: {"Allow insecure SSL connections"},
		configuration.AnnotationIdeKey:      {"insecure"},
	})
	registerFlag(fs, SettingAutoConfigureMcpServer, "", "Auto-configure Snyk MCP server", map[string][]string{
		configuration.AnnotationScope:       {"machine"},
		configuration.AnnotationRemoteKey:   {"auto_configure_mcp_server"},
		configuration.AnnotationDisplayName: {"Auto Configure MCP Server"},
		configuration.AnnotationDescription: {"Automatically configure the Snyk MCP server"},
		configuration.AnnotationIdeKey:      {"autoConfigureSnykMcpServer"},
	})
	registerFlag(fs, SettingPublishSecurityAtInceptionRules, "", "Publish security at inception rules", map[string][]string{
		configuration.AnnotationScope:       {"machine"},
		configuration.AnnotationRemoteKey:   {"publish_security_at_inception_rules"},
		configuration.AnnotationDisplayName: {"Publish Security At Inception Rules"},
		configuration.AnnotationDescription: {"Publish security rules at inception"},
		configuration.AnnotationIdeKey:      {"publishSecurityAtInceptionRules"},
	})
	registerFlag(fs, SettingTrustEnabled, "", "Enable trusted folders feature", map[string][]string{
		configuration.AnnotationScope:       {"machine"},
		configuration.AnnotationRemoteKey:   {"trust_enabled"},
		configuration.AnnotationDisplayName: {"Trust Enabled"},
		configuration.AnnotationDescription: {"Enable the trusted folders feature"},
		configuration.AnnotationIdeKey:      {"enableTrustedFoldersFeature"},
	})
	registerFlag(fs, SettingBinaryBaseUrl, "", "CLI binary base download URL", map[string][]string{
		configuration.AnnotationScope:       {"machine"},
		configuration.AnnotationRemoteKey:   {"binary_base_url"},
		configuration.AnnotationDisplayName: {"Binary Base URL"},
		configuration.AnnotationDescription: {"Base URL for CLI binary downloads"},
		configuration.AnnotationIdeKey:      {"cliBaseDownloadURL"},
	})
	registerFlag(fs, SettingCliPath, "", "Path to Snyk CLI", map[string][]string{
		configuration.AnnotationScope:       {"machine"},
		configuration.AnnotationRemoteKey:   {"cli_path"},
		configuration.AnnotationDisplayName: {"CLI Path"},
		configuration.AnnotationDescription: {"Path to the Snyk CLI executable"},
		configuration.AnnotationIdeKey:      {"cliPath"},
	})
	registerFlag(fs, SettingAutomaticDownload, "", "Manage binaries automatically", map[string][]string{
		configuration.AnnotationScope:       {"machine"},
		configuration.AnnotationRemoteKey:   {"automatic_download"},
		configuration.AnnotationDisplayName: {"Automatic Download"},
		configuration.AnnotationDescription: {"Automatically download and manage binaries"},
		configuration.AnnotationIdeKey:      {"manageBinariesAutomatically"},
	})
	registerFlag(fs, SettingCliReleaseChannel, "", "CLI release channel", map[string][]string{
		configuration.AnnotationScope:       {"machine"},
		configuration.AnnotationRemoteKey:   {"cli_release_channel"},
		configuration.AnnotationDisplayName: {"CLI Release Channel"},
		configuration.AnnotationDescription: {"Release channel for CLI updates"},
		configuration.AnnotationIdeKey:      {"cliReleaseChannel"},
	})
	registerFlag(fs, SettingOrganization, "", "Default organization", map[string][]string{
		configuration.AnnotationScope:       {"machine"},
		configuration.AnnotationDisplayName: {"Organization"},
		configuration.AnnotationDescription: {"Default Snyk organization"},
		configuration.AnnotationIdeKey:      {"organization"},
	})
	registerFlag(fs, SettingAutomaticAuthentication, false, "Automatic authentication", map[string][]string{
		configuration.AnnotationScope:       {"machine"},
		configuration.AnnotationDisplayName: {"Automatic Authentication"},
		configuration.AnnotationDescription: {"Enable automatic authentication"},
		configuration.AnnotationIdeKey:      {"automaticAuthentication"},
	})

	// Org-scope settings (13)
	registerFlag(fs, SettingEnabledSeverities, "", "Enabled severity filter", map[string][]string{
		configuration.AnnotationScope:       {"org"},
		configuration.AnnotationRemoteKey:   {"severities"},
		configuration.AnnotationDisplayName: {"Enabled Severities"},
		configuration.AnnotationDescription: {"Severity filter for findings"},
		configuration.AnnotationIdeKey:      {"filterSeverity"},
	})
	registerFlag(fs, SettingRiskScoreThreshold, 0, "Risk score threshold (0-1000)", map[string][]string{
		configuration.AnnotationScope:       {"org"},
		configuration.AnnotationRemoteKey:   {"risk_score_threshold"},
		configuration.AnnotationDisplayName: {"Risk Score Threshold"},
		configuration.AnnotationDescription: {"Minimum risk score for findings (0-1000)"},
		configuration.AnnotationIdeKey:      {"riskScoreThreshold"},
	})
	registerFlag(fs, SettingCweIds, "", "CWE IDs filter", map[string][]string{
		configuration.AnnotationScope:       {"org"},
		configuration.AnnotationRemoteKey:   {"cwe"},
		configuration.AnnotationDisplayName: {"CWE IDs"},
		configuration.AnnotationDescription: {"Comma-separated CWE IDs to filter"},
	})
	registerFlag(fs, SettingCveIds, "", "CVE IDs filter", map[string][]string{
		configuration.AnnotationScope:       {"org"},
		configuration.AnnotationRemoteKey:   {"cve"},
		configuration.AnnotationDisplayName: {"CVE IDs"},
		configuration.AnnotationDescription: {"Comma-separated CVE IDs to filter"},
	})
	registerFlag(fs, SettingRuleIds, "", "Rule IDs filter", map[string][]string{
		configuration.AnnotationScope:       {"org"},
		configuration.AnnotationRemoteKey:   {"rule"},
		configuration.AnnotationDisplayName: {"Rule IDs"},
		configuration.AnnotationDescription: {"Comma-separated rule IDs to filter"},
	})
	registerFlag(fs, SettingSnykCodeEnabled, false, "Enable Snyk Code", map[string][]string{
		configuration.AnnotationScope:       {"org"},
		configuration.AnnotationDisplayName: {"Snyk Code Enabled"},
		configuration.AnnotationDescription: {"Enable Snyk Code security analysis"},
		configuration.AnnotationIdeKey:      {"activateSnykCode"},
	})
	registerFlag(fs, SettingSnykOssEnabled, false, "Enable Snyk Open Source", map[string][]string{
		configuration.AnnotationScope:       {"org"},
		configuration.AnnotationDisplayName: {"Snyk OSS Enabled"},
		configuration.AnnotationDescription: {"Enable Snyk Open Source analysis"},
		configuration.AnnotationIdeKey:      {"activateSnykOpenSource"},
	})
	registerFlag(fs, SettingSnykIacEnabled, false, "Enable Snyk IaC", map[string][]string{
		configuration.AnnotationScope:       {"org"},
		configuration.AnnotationDisplayName: {"Snyk IaC Enabled"},
		configuration.AnnotationDescription: {"Enable Snyk Infrastructure as Code analysis"},
		configuration.AnnotationIdeKey:      {"activateSnykIac"},
	})
	registerFlag(fs, SettingSnykSecretsEnabled, false, "Enable Snyk Secrets", map[string][]string{
		configuration.AnnotationScope:       {"org"},
		configuration.AnnotationDisplayName: {"Snyk Secrets Enabled"},
		configuration.AnnotationDescription: {"Enable Snyk Secrets detection"},
		configuration.AnnotationIdeKey:      {"activateSnykSecrets"},
	})
	registerFlag(fs, SettingScanAutomatic, "", "Automatic scan mode", map[string][]string{
		configuration.AnnotationScope:       {"org"},
		configuration.AnnotationRemoteKey:   {"automatic"},
		configuration.AnnotationDisplayName: {"Scan Automatic"},
		configuration.AnnotationDescription: {"Enable automatic scanning"},
		configuration.AnnotationIdeKey:      {"scanningMode"},
	})
	registerFlag(fs, SettingScanNetNew, "", "Enable delta findings", map[string][]string{
		configuration.AnnotationScope:       {"org"},
		configuration.AnnotationRemoteKey:   {"net_new"},
		configuration.AnnotationDisplayName: {"Scan Net New"},
		configuration.AnnotationDescription: {"Enable net-new/delta findings"},
		configuration.AnnotationIdeKey:      {"enableDeltaFindings"},
	})
	registerFlag(fs, SettingIssueViewOpenIssues, false, "Show open issues in view", map[string][]string{
		configuration.AnnotationScope:       {"org"},
		configuration.AnnotationRemoteKey:   {"open_issues"},
		configuration.AnnotationDisplayName: {"Issue View Open Issues"},
		configuration.AnnotationDescription: {"Show open issues in view"},
	})
	registerFlag(fs, SettingIssueViewIgnoredIssues, false, "Show ignored issues in view", map[string][]string{
		configuration.AnnotationScope:       {"org"},
		configuration.AnnotationRemoteKey:   {"ignored_issues"},
		configuration.AnnotationDisplayName: {"Issue View Ignored Issues"},
		configuration.AnnotationDescription: {"Show ignored issues in view"},
	})

	// Folder-scope settings (4)
	registerFlag(fs, SettingReferenceFolder, "", "Reference folder path", map[string][]string{
		configuration.AnnotationScope:       {"folder"},
		configuration.AnnotationRemoteKey:   {"reference_folder"},
		configuration.AnnotationDisplayName: {"Reference Folder"},
		configuration.AnnotationDescription: {"Path to reference folder for baseline"},
	})
	registerFlag(fs, SettingReferenceBranch, "", "Reference branch for baseline", map[string][]string{
		configuration.AnnotationScope:       {"folder"},
		configuration.AnnotationRemoteKey:   {"reference_branch"},
		configuration.AnnotationDisplayName: {"Reference Branch"},
		configuration.AnnotationDescription: {"Branch used as baseline for net-new findings"},
	})
	registerFlag(fs, SettingAdditionalParameters, "", "Additional CLI parameters", map[string][]string{
		configuration.AnnotationScope:       {"folder"},
		configuration.AnnotationRemoteKey:   {"additional_parameters"},
		configuration.AnnotationDisplayName: {"Additional Parameters"},
		configuration.AnnotationDescription: {"Additional parameters passed to CLI"},
		configuration.AnnotationIdeKey:      {"additionalParams"},
	})
	registerFlag(fs, SettingAdditionalEnvironment, "", "Additional environment variables", map[string][]string{
		configuration.AnnotationScope:       {"folder"},
		configuration.AnnotationRemoteKey:   {"additional_environment"},
		configuration.AnnotationDisplayName: {"Additional Environment"},
		configuration.AnnotationDescription: {"Additional environment variables for CLI"},
		configuration.AnnotationIdeKey:      {"additionalEnv"},
	})
	registerFlag(fs, SettingBaseBranch, "", "Base branch for delta scanning", map[string][]string{
		configuration.AnnotationScope:       {"folder"},
		configuration.AnnotationDisplayName: {"Base Branch"},
		configuration.AnnotationDescription: {"Base branch for delta findings comparison"},
		configuration.AnnotationIdeKey:      {"baseBranch"},
	})
	registerFlag(fs, SettingLocalBranches, "", "Local branches", map[string][]string{
		configuration.AnnotationScope:       {"folder"},
		configuration.AnnotationDisplayName: {"Local Branches"},
		configuration.AnnotationDescription: {"Available local branches (enriched by LS from git)"},
	})
	registerFlag(fs, SettingPreferredOrg, "", "Preferred organization for this folder", map[string][]string{
		configuration.AnnotationScope:       {"folder"},
		configuration.AnnotationDisplayName: {"Preferred Organization"},
		configuration.AnnotationDescription: {"Organization to use when operating on this folder"},
		configuration.AnnotationIdeKey:      {"preferredOrg"},
	})
	registerFlag(fs, SettingAutoDeterminedOrg, "", "Auto-determined organization", map[string][]string{
		configuration.AnnotationScope:       {"folder"},
		configuration.AnnotationDisplayName: {"Auto-Determined Organization"},
		configuration.AnnotationDescription: {"Organization automatically determined by LDX-Sync"},
	})
	registerFlag(fs, SettingOrgSetByUser, false, "Organization set by user", map[string][]string{
		configuration.AnnotationScope:       {"folder"},
		configuration.AnnotationDisplayName: {"Organization Set By User"},
		configuration.AnnotationDescription: {"Whether the user explicitly chose the organization"},
		configuration.AnnotationIdeKey:      {"orgSetByUser"},
	})
	registerFlag(fs, SettingScanCommandConfig, "", "Scan command configuration", map[string][]string{
		configuration.AnnotationScope:       {"folder"},
		configuration.AnnotationDisplayName: {"Scan Command Config"},
		configuration.AnnotationDescription: {"Custom scan command configuration per product"},
		configuration.AnnotationIdeKey:      {"scanCommandConfig"},
	})
	registerFlag(fs, SettingSastSettings, "", "SAST settings from Snyk API", map[string][]string{
		configuration.AnnotationScope:       {"folder"},
		configuration.AnnotationDisplayName: {"SAST Settings"},
		configuration.AnnotationDescription: {"SAST configuration from Snyk API (autofix, local code engine)"},
	})

	// Write-only settings (accepted IDE→LS, NOT sent LS→IDE)
	registerFlag(fs, SettingToken, "", "Authentication token", map[string][]string{
		configuration.AnnotationScope:       {"machine"},
		configuration.AnnotationWriteOnly:   {"true"},
		configuration.AnnotationDisplayName: {"Token"},
		configuration.AnnotationDescription: {"Snyk authentication token"},
		configuration.AnnotationIdeKey:      {"token"},
	})
	registerFlag(fs, SettingSendErrorReports, false, "Send error reports", map[string][]string{
		configuration.AnnotationScope:       {"machine"},
		configuration.AnnotationWriteOnly:   {"true"},
		configuration.AnnotationDisplayName: {"Send Error Reports"},
		configuration.AnnotationDescription: {"Enable sending error reports to Snyk"},
		configuration.AnnotationIdeKey:      {"sendErrorReports"},
	})
	registerFlag(fs, SettingEnableSnykLearnCodeActions, false, "Enable Snyk Learn code actions", map[string][]string{
		configuration.AnnotationScope:       {"machine"},
		configuration.AnnotationWriteOnly:   {"true"},
		configuration.AnnotationDisplayName: {"Snyk Learn Code Actions"},
		configuration.AnnotationDescription: {"Enable Snyk Learn code actions"},
		configuration.AnnotationIdeKey:      {"enableSnykLearnCodeActions"},
	})
	registerFlag(fs, SettingEnableSnykOssQuickFixActions, false, "Enable Snyk OSS quick fix code actions", map[string][]string{
		configuration.AnnotationScope:       {"machine"},
		configuration.AnnotationWriteOnly:   {"true"},
		configuration.AnnotationDisplayName: {"Snyk OSS Quick Fix Code Actions"},
		configuration.AnnotationDescription: {"Enable Snyk OSS quick fix code actions"},
		configuration.AnnotationIdeKey:      {"enableSnykOSSQuickFixCodeActions"},
	})
	registerFlag(fs, SettingEnableSnykOpenBrowserActions, false, "Enable Snyk open browser actions", map[string][]string{
		configuration.AnnotationScope:       {"machine"},
		configuration.AnnotationWriteOnly:   {"true"},
		configuration.AnnotationDisplayName: {"Snyk Open Browser Actions"},
		configuration.AnnotationDescription: {"Enable Snyk open browser actions"},
		configuration.AnnotationIdeKey:      {"enableSnykOpenBrowserActions"},
	})
}

func registerFlag(fs *pflag.FlagSet, name string, defaultVal any, usage string, annotations map[string][]string) {
	switch v := defaultVal.(type) {
	case bool:
		fs.Bool(name, v, usage)
	case int:
		fs.Int(name, v, usage)
	case string:
		fs.String(name, v, usage)
	default:
		panic("registerFlag: unsupported type for flag " + name)
	}
	fs.Lookup(name).Annotations = annotations
}
