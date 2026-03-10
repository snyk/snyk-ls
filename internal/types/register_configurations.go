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
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/spf13/pflag"
)

// RegisterAllConfigurations registers all snyk-ls configuration flags with their annotations
// into the given FlagSet. Flags are annotated with config.scope, config.remoteKey,
// config.displayName, config.description, and config.ideKey for framework integration.
func RegisterAllConfigurations(fs *pflag.FlagSet) {
	// Machine-scope settings (14)
	registerFlag(fs, SettingApiEndpoint, "", "API endpoint URL", map[string][]string{
		configresolver.AnnotationScope:       {"machine"},
		configresolver.AnnotationRemoteKey:   {"api_endpoint"},
		configresolver.AnnotationDisplayName: {"API Endpoint"},
		configresolver.AnnotationDescription: {"The Snyk API endpoint URL"},
		configresolver.AnnotationIdeKey:      {"endpoint"},
	})
	registerFlag(fs, SettingCodeEndpoint, "", "Code API endpoint URL", map[string][]string{
		configresolver.AnnotationScope:       {"machine"},
		configresolver.AnnotationRemoteKey:   {"code_endpoint"},
		configresolver.AnnotationDisplayName: {"Code API Endpoint"},
		configresolver.AnnotationDescription: {"The Snyk Code API endpoint URL"},
		configresolver.AnnotationIdeKey:      {"snykCodeApi"},
	})
	registerFlag(fs, SettingAuthenticationMethod, "", "Authentication method", map[string][]string{
		configresolver.AnnotationScope:       {"machine"},
		configresolver.AnnotationRemoteKey:   {"authentication_method"},
		configresolver.AnnotationDisplayName: {"Authentication Method"},
		configresolver.AnnotationDescription: {"Authentication method (token, oauth, pat)"},
		configresolver.AnnotationIdeKey:      {"authenticationMethod"},
	})
	registerFlag(fs, SettingProxyHttp, "", "HTTP proxy URL", map[string][]string{
		configresolver.AnnotationScope:       {"machine"},
		configresolver.AnnotationRemoteKey:   {"proxy_http"},
		configresolver.AnnotationDisplayName: {"Proxy HTTP"},
		configresolver.AnnotationDescription: {"HTTP proxy URL"},
		configresolver.AnnotationIdeKey:      {"proxyHttp"},
	})
	registerFlag(fs, SettingProxyHttps, "", "HTTPS proxy URL", map[string][]string{
		configresolver.AnnotationScope:       {"machine"},
		configresolver.AnnotationRemoteKey:   {"proxy_https"},
		configresolver.AnnotationDisplayName: {"Proxy HTTPS"},
		configresolver.AnnotationDescription: {"HTTPS proxy URL"},
		configresolver.AnnotationIdeKey:      {"proxyHttps"},
	})
	registerFlag(fs, SettingProxyNoProxy, "", "No proxy list", map[string][]string{
		configresolver.AnnotationScope:       {"machine"},
		configresolver.AnnotationRemoteKey:   {"proxy_no_proxy"},
		configresolver.AnnotationDisplayName: {"Proxy No Proxy"},
		configresolver.AnnotationDescription: {"Comma-separated list of hosts to bypass proxy"},
		configresolver.AnnotationIdeKey:      {"proxyNoProxy"},
	})
	registerFlag(fs, SettingProxyInsecure, "", "Allow insecure SSL connections", map[string][]string{
		configresolver.AnnotationScope:       {"machine"},
		configresolver.AnnotationRemoteKey:   {"proxy_insecure"},
		configresolver.AnnotationDisplayName: {"Proxy Insecure"},
		configresolver.AnnotationDescription: {"Allow insecure SSL connections"},
		configresolver.AnnotationIdeKey:      {"insecure"},
	})
	registerFlag(fs, SettingAutoConfigureMcpServer, "", "Auto-configure Snyk MCP server", map[string][]string{
		configresolver.AnnotationScope:       {"machine"},
		configresolver.AnnotationRemoteKey:   {"auto_configure_mcp_server"},
		configresolver.AnnotationDisplayName: {"Auto Configure MCP Server"},
		configresolver.AnnotationDescription: {"Automatically configure the Snyk MCP server"},
		configresolver.AnnotationIdeKey:      {"autoConfigureSnykMcpServer"},
	})
	registerFlag(fs, SettingPublishSecurityAtInceptionRules, "", "Publish security at inception rules", map[string][]string{
		configresolver.AnnotationScope:       {"machine"},
		configresolver.AnnotationRemoteKey:   {"publish_security_at_inception_rules"},
		configresolver.AnnotationDisplayName: {"Publish Security At Inception Rules"},
		configresolver.AnnotationDescription: {"Publish security rules at inception"},
		configresolver.AnnotationIdeKey:      {"publishSecurityAtInceptionRules"},
	})
	registerFlag(fs, SettingTrustEnabled, "", "Enable trusted folders feature", map[string][]string{
		configresolver.AnnotationScope:       {"machine"},
		configresolver.AnnotationRemoteKey:   {"trust_enabled"},
		configresolver.AnnotationDisplayName: {"Trust Enabled"},
		configresolver.AnnotationDescription: {"Enable the trusted folders feature"},
		configresolver.AnnotationIdeKey:      {"enableTrustedFoldersFeature"},
	})
	registerFlag(fs, SettingBinaryBaseUrl, "", "CLI binary base download URL", map[string][]string{
		configresolver.AnnotationScope:       {"machine"},
		configresolver.AnnotationRemoteKey:   {"binary_base_url"},
		configresolver.AnnotationDisplayName: {"Binary Base URL"},
		configresolver.AnnotationDescription: {"Base URL for CLI binary downloads"},
		configresolver.AnnotationIdeKey:      {"cliBaseDownloadURL"},
	})
	registerFlag(fs, SettingCliPath, "", "Path to Snyk CLI", map[string][]string{
		configresolver.AnnotationScope:       {"machine"},
		configresolver.AnnotationRemoteKey:   {"cli_path"},
		configresolver.AnnotationDisplayName: {"CLI Path"},
		configresolver.AnnotationDescription: {"Path to the Snyk CLI executable"},
		configresolver.AnnotationIdeKey:      {"cliPath"},
	})
	registerFlag(fs, SettingAutomaticDownload, "", "Manage binaries automatically", map[string][]string{
		configresolver.AnnotationScope:       {"machine"},
		configresolver.AnnotationRemoteKey:   {"automatic_download"},
		configresolver.AnnotationDisplayName: {"Automatic Download"},
		configresolver.AnnotationDescription: {"Automatically download and manage binaries"},
		configresolver.AnnotationIdeKey:      {"manageBinariesAutomatically"},
	})
	registerFlag(fs, SettingCliReleaseChannel, "", "CLI release channel", map[string][]string{
		configresolver.AnnotationScope:       {"machine"},
		configresolver.AnnotationRemoteKey:   {"cli_release_channel"},
		configresolver.AnnotationDisplayName: {"CLI Release Channel"},
		configresolver.AnnotationDescription: {"Release channel for CLI updates"},
		configresolver.AnnotationIdeKey:      {"cliReleaseChannel"},
	})
	registerFlag(fs, SettingOrganization, "", "Default organization", map[string][]string{
		configresolver.AnnotationScope:       {"machine"},
		configresolver.AnnotationDisplayName: {"Organization"},
		configresolver.AnnotationDescription: {"Default Snyk organization"},
		configresolver.AnnotationIdeKey:      {"organization"},
	})
	registerFlag(fs, SettingAutomaticAuthentication, false, "Automatic authentication", map[string][]string{
		configresolver.AnnotationScope:       {"machine"},
		configresolver.AnnotationDisplayName: {"Automatic Authentication"},
		configresolver.AnnotationDescription: {"Enable automatic authentication"},
		configresolver.AnnotationIdeKey:      {"automaticAuthentication"},
	})

	// Org-scope settings (13)
	registerFlag(fs, SettingEnabledSeverities, "", "Enabled severity filter", map[string][]string{
		configresolver.AnnotationScope:       {"org"},
		configresolver.AnnotationRemoteKey:   {"severities"},
		configresolver.AnnotationDisplayName: {"Enabled Severities"},
		configresolver.AnnotationDescription: {"Severity filter for findings"},
		configresolver.AnnotationIdeKey:      {"filterSeverity"},
	})
	registerFlag(fs, SettingRiskScoreThreshold, 0, "Risk score threshold (0-1000)", map[string][]string{
		configresolver.AnnotationScope:       {"org"},
		configresolver.AnnotationRemoteKey:   {"risk_score_threshold"},
		configresolver.AnnotationDisplayName: {"Risk Score Threshold"},
		configresolver.AnnotationDescription: {"Minimum risk score for findings (0-1000)"},
		configresolver.AnnotationIdeKey:      {"riskScoreThreshold"},
	})
	registerFlag(fs, SettingCweIds, "", "CWE IDs filter", map[string][]string{
		configresolver.AnnotationScope:       {"org"},
		configresolver.AnnotationRemoteKey:   {"cwe"},
		configresolver.AnnotationDisplayName: {"CWE IDs"},
		configresolver.AnnotationDescription: {"Comma-separated CWE IDs to filter"},
	})
	registerFlag(fs, SettingCveIds, "", "CVE IDs filter", map[string][]string{
		configresolver.AnnotationScope:       {"org"},
		configresolver.AnnotationRemoteKey:   {"cve"},
		configresolver.AnnotationDisplayName: {"CVE IDs"},
		configresolver.AnnotationDescription: {"Comma-separated CVE IDs to filter"},
	})
	registerFlag(fs, SettingRuleIds, "", "Rule IDs filter", map[string][]string{
		configresolver.AnnotationScope:       {"org"},
		configresolver.AnnotationRemoteKey:   {"rule"},
		configresolver.AnnotationDisplayName: {"Rule IDs"},
		configresolver.AnnotationDescription: {"Comma-separated rule IDs to filter"},
	})
	registerFlag(fs, SettingSnykCodeEnabled, false, "Enable Snyk Code", map[string][]string{
		configresolver.AnnotationScope:       {"org"},
		configresolver.AnnotationDisplayName: {"Snyk Code Enabled"},
		configresolver.AnnotationDescription: {"Enable Snyk Code security analysis"},
		configresolver.AnnotationIdeKey:      {"activateSnykCode"},
	})
	registerFlag(fs, SettingSnykOssEnabled, false, "Enable Snyk Open Source", map[string][]string{
		configresolver.AnnotationScope:       {"org"},
		configresolver.AnnotationDisplayName: {"Snyk OSS Enabled"},
		configresolver.AnnotationDescription: {"Enable Snyk Open Source analysis"},
		configresolver.AnnotationIdeKey:      {"activateSnykOpenSource"},
	})
	registerFlag(fs, SettingSnykIacEnabled, false, "Enable Snyk IaC", map[string][]string{
		configresolver.AnnotationScope:       {"org"},
		configresolver.AnnotationDisplayName: {"Snyk IaC Enabled"},
		configresolver.AnnotationDescription: {"Enable Snyk Infrastructure as Code analysis"},
		configresolver.AnnotationIdeKey:      {"activateSnykIac"},
	})
	registerFlag(fs, SettingSnykSecretsEnabled, false, "Enable Snyk Secrets", map[string][]string{
		configresolver.AnnotationScope:       {"org"},
		configresolver.AnnotationDisplayName: {"Snyk Secrets Enabled"},
		configresolver.AnnotationDescription: {"Enable Snyk Secrets detection"},
		configresolver.AnnotationIdeKey:      {"activateSnykSecrets"},
	})
	registerFlag(fs, SettingScanAutomatic, "", "Automatic scan mode", map[string][]string{
		configresolver.AnnotationScope:       {"org"},
		configresolver.AnnotationRemoteKey:   {"automatic"},
		configresolver.AnnotationDisplayName: {"Scan Automatic"},
		configresolver.AnnotationDescription: {"Enable automatic scanning"},
		configresolver.AnnotationIdeKey:      {"scanningMode"},
	})
	registerFlag(fs, SettingScanNetNew, "", "Enable delta findings", map[string][]string{
		configresolver.AnnotationScope:       {"org"},
		configresolver.AnnotationRemoteKey:   {"net_new"},
		configresolver.AnnotationDisplayName: {"Scan Net New"},
		configresolver.AnnotationDescription: {"Enable net-new/delta findings"},
		configresolver.AnnotationIdeKey:      {"enableDeltaFindings"},
	})
	registerFlag(fs, SettingIssueViewOpenIssues, false, "Show open issues in view", map[string][]string{
		configresolver.AnnotationScope:       {"org"},
		configresolver.AnnotationRemoteKey:   {"open_issues"},
		configresolver.AnnotationDisplayName: {"Issue View Open Issues"},
		configresolver.AnnotationDescription: {"Show open issues in view"},
	})
	registerFlag(fs, SettingIssueViewIgnoredIssues, false, "Show ignored issues in view", map[string][]string{
		configresolver.AnnotationScope:       {"org"},
		configresolver.AnnotationRemoteKey:   {"ignored_issues"},
		configresolver.AnnotationDisplayName: {"Issue View Ignored Issues"},
		configresolver.AnnotationDescription: {"Show ignored issues in view"},
	})

	// Folder-scope settings (4)
	registerFlag(fs, SettingReferenceFolder, "", "Reference folder path", map[string][]string{
		configresolver.AnnotationScope:       {"folder"},
		configresolver.AnnotationRemoteKey:   {"reference_folder"},
		configresolver.AnnotationDisplayName: {"Reference Folder"},
		configresolver.AnnotationDescription: {"Path to reference folder for baseline"},
	})
	registerFlag(fs, SettingReferenceBranch, "", "Reference branch for baseline", map[string][]string{
		configresolver.AnnotationScope:       {"folder"},
		configresolver.AnnotationRemoteKey:   {"reference_branch"},
		configresolver.AnnotationDisplayName: {"Reference Branch"},
		configresolver.AnnotationDescription: {"Branch used as baseline for net-new findings"},
	})
	registerFlag(fs, SettingAdditionalParameters, "", "Additional CLI parameters", map[string][]string{
		configresolver.AnnotationScope:       {"folder"},
		configresolver.AnnotationRemoteKey:   {"additional_parameters"},
		configresolver.AnnotationDisplayName: {"Additional Parameters"},
		configresolver.AnnotationDescription: {"Additional parameters passed to CLI"},
		configresolver.AnnotationIdeKey:      {"additionalParams"},
	})
	registerFlag(fs, SettingAdditionalEnvironment, "", "Additional environment variables", map[string][]string{
		configresolver.AnnotationScope:       {"folder"},
		configresolver.AnnotationRemoteKey:   {"additional_environment"},
		configresolver.AnnotationDisplayName: {"Additional Environment"},
		configresolver.AnnotationDescription: {"Additional environment variables for CLI"},
		configresolver.AnnotationIdeKey:      {"additionalEnv"},
	})
	registerFlag(fs, SettingBaseBranch, "", "Base branch for delta scanning", map[string][]string{
		configresolver.AnnotationScope:       {"folder"},
		configresolver.AnnotationDisplayName: {"Base Branch"},
		configresolver.AnnotationDescription: {"Base branch for delta findings comparison"},
		configresolver.AnnotationIdeKey:      {"baseBranch"},
	})
	registerFlag(fs, SettingLocalBranches, "", "Local branches", map[string][]string{
		configresolver.AnnotationScope:       {"folder"},
		configresolver.AnnotationDisplayName: {"Local Branches"},
		configresolver.AnnotationDescription: {"Available local branches (enriched by LS from git)"},
	})
	registerFlag(fs, SettingPreferredOrg, "", "Preferred organization for this folder", map[string][]string{
		configresolver.AnnotationScope:       {"folder"},
		configresolver.AnnotationDisplayName: {"Preferred Organization"},
		configresolver.AnnotationDescription: {"Organization to use when operating on this folder"},
		configresolver.AnnotationIdeKey:      {"preferredOrg"},
	})
	registerFlag(fs, SettingAutoDeterminedOrg, "", "Auto-determined organization", map[string][]string{
		configresolver.AnnotationScope:       {"folder"},
		configresolver.AnnotationDisplayName: {"Auto-Determined Organization"},
		configresolver.AnnotationDescription: {"Organization automatically determined by LDX-Sync"},
	})
	registerFlag(fs, SettingOrgSetByUser, false, "Organization set by user", map[string][]string{
		configresolver.AnnotationScope:       {"folder"},
		configresolver.AnnotationDisplayName: {"Organization Set By User"},
		configresolver.AnnotationDescription: {"Whether the user explicitly chose the organization"},
		configresolver.AnnotationIdeKey:      {"orgSetByUser"},
	})
	registerFlag(fs, SettingScanCommandConfig, "", "Scan command configuration", map[string][]string{
		configresolver.AnnotationScope:       {"folder"},
		configresolver.AnnotationDisplayName: {"Scan Command Config"},
		configresolver.AnnotationDescription: {"Custom scan command configuration per product"},
		configresolver.AnnotationIdeKey:      {"scanCommandConfig"},
	})
	registerFlag(fs, SettingSastSettings, "", "SAST settings from Snyk API", map[string][]string{
		configresolver.AnnotationScope:       {"folder"},
		configresolver.AnnotationDisplayName: {"SAST Settings"},
		configresolver.AnnotationDescription: {"SAST configuration from Snyk API (autofix, local code engine)"},
	})

	// Write-only settings (accepted IDE→LS, NOT sent LS→IDE)
	registerFlag(fs, SettingToken, "", "Authentication token", map[string][]string{
		configresolver.AnnotationScope:       {"machine"},
		configresolver.AnnotationWriteOnly:   {"true"},
		configresolver.AnnotationDisplayName: {"Token"},
		configresolver.AnnotationDescription: {"Snyk authentication token"},
		configresolver.AnnotationIdeKey:      {"token"},
	})
	registerFlag(fs, SettingSendErrorReports, false, "Send error reports", map[string][]string{
		configresolver.AnnotationScope:       {"machine"},
		configresolver.AnnotationWriteOnly:   {"true"},
		configresolver.AnnotationDisplayName: {"Send Error Reports"},
		configresolver.AnnotationDescription: {"Enable sending error reports to Snyk"},
		configresolver.AnnotationIdeKey:      {"sendErrorReports"},
	})
	registerFlag(fs, SettingEnableSnykLearnCodeActions, false, "Enable Snyk Learn code actions", map[string][]string{
		configresolver.AnnotationScope:       {"machine"},
		configresolver.AnnotationWriteOnly:   {"true"},
		configresolver.AnnotationDisplayName: {"Snyk Learn Code Actions"},
		configresolver.AnnotationDescription: {"Enable Snyk Learn code actions"},
		configresolver.AnnotationIdeKey:      {"enableSnykLearnCodeActions"},
	})
	registerFlag(fs, SettingEnableSnykOssQuickFixActions, false, "Enable Snyk OSS quick fix code actions", map[string][]string{
		configresolver.AnnotationScope:       {"machine"},
		configresolver.AnnotationWriteOnly:   {"true"},
		configresolver.AnnotationDisplayName: {"Snyk OSS Quick Fix Code Actions"},
		configresolver.AnnotationDescription: {"Enable Snyk OSS quick fix code actions"},
		configresolver.AnnotationIdeKey:      {"enableSnykOSSQuickFixCodeActions"},
	})
	registerFlag(fs, SettingEnableSnykOpenBrowserActions, false, "Enable Snyk open browser actions", map[string][]string{
		configresolver.AnnotationScope:       {"machine"},
		configresolver.AnnotationWriteOnly:   {"true"},
		configresolver.AnnotationDisplayName: {"Snyk Open Browser Actions"},
		configresolver.AnnotationDescription: {"Enable Snyk open browser actions"},
		configresolver.AnnotationIdeKey:      {"enableSnykOpenBrowserActions"},
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
