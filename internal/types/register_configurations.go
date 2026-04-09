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
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
)

// RegisterAllConfigurations registers all snyk-ls configuration flags with their annotations
// into the given FlagSet. Flags are annotated with config.scope, config.remoteKey,
// config.displayName, config.description, and config.ideKey for framework integration.
func RegisterAllConfigurations(fs *pflag.FlagSet) {
	// Machine-scope settings
	machineScope := string(configresolver.MachineScope)
	registerFlag(fs, SettingApiEndpoint, DefaultSnykApiUrl, "API endpoint URL", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationRemoteKey:   {"api_endpoint"},
		configresolver.AnnotationDisplayName: {"API Endpoint"},
		configresolver.AnnotationDescription: {"The Snyk API endpoint URL"},
	})
	registerFlag(fs, SettingCodeEndpoint, "", "Code API endpoint URL", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationRemoteKey:   {"code_endpoint"},
		configresolver.AnnotationDisplayName: {"Code API Endpoint"},
		configresolver.AnnotationDescription: {"The Snyk Code API endpoint URL"},
	})
	registerFlag(fs, SettingAuthenticationMethod, string(OAuthAuthentication), "Authentication method", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationRemoteKey:   {"authentication_method"},
		configresolver.AnnotationDisplayName: {"Authentication Method"},
		configresolver.AnnotationDescription: {"Authentication method (token, oauth, pat)"},
	})
	registerFlag(fs, SettingProxyHttp, "", "HTTP proxy URL", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationRemoteKey:   {"proxy_http"},
		configresolver.AnnotationDisplayName: {"Proxy HTTP"},
		configresolver.AnnotationDescription: {"HTTP proxy URL"},
	})
	registerFlag(fs, SettingProxyHttps, "", "HTTPS proxy URL", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationRemoteKey:   {"proxy_https"},
		configresolver.AnnotationDisplayName: {"Proxy HTTPS"},
		configresolver.AnnotationDescription: {"HTTPS proxy URL"},
	})
	registerFlag(fs, SettingProxyNoProxy, "", "No proxy list", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationRemoteKey:   {"proxy_no_proxy"},
		configresolver.AnnotationDisplayName: {"Proxy No Proxy"},
		configresolver.AnnotationDescription: {"Comma-separated list of hosts to bypass proxy"},
	})
	registerFlag(fs, SettingProxyInsecure, false, "Allow insecure SSL connections", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationRemoteKey:   {"proxy_insecure"},
		configresolver.AnnotationDisplayName: {"Proxy Insecure"},
		configresolver.AnnotationDescription: {"Allow insecure SSL connections"},
	})
	registerFlag(fs, SettingAutoConfigureMcpServer, "", "Auto-configure Snyk MCP server", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationRemoteKey:   {"auto_configure_mcp_server"},
		configresolver.AnnotationDisplayName: {"Auto Configure MCP Server"},
		configresolver.AnnotationDescription: {"Automatically configure the Snyk MCP server"},
	})
	registerFlag(fs, SettingPublishSecurityAtInceptionRules, "", "Publish security at inception rules", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationRemoteKey:   {"publish_security_at_inception_rules"},
		configresolver.AnnotationDisplayName: {"Publish Security At Inception Rules"},
		configresolver.AnnotationDescription: {"Publish security rules at inception"},
	})
	registerFlag(fs, SettingTrustEnabled, true, "Enable trusted folders feature", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationRemoteKey:   {"trust_enabled"},
		configresolver.AnnotationDisplayName: {"Trust Enabled"},
		configresolver.AnnotationDescription: {"Enable the trusted folders feature"},
	})
	registerFlag(fs, SettingBinaryBaseUrl, "", "CLI binary base download URL", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationRemoteKey:   {"binary_base_url"},
		configresolver.AnnotationDisplayName: {"Binary Base URL"},
		configresolver.AnnotationDescription: {"Base URL for CLI binary downloads"},
	})
	registerFlag(fs, SettingCliPath, DefaultCliPath(), "Path to Snyk CLI", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationRemoteKey:   {"cli_path"},
		configresolver.AnnotationDisplayName: {"CLI Path"},
		configresolver.AnnotationDescription: {"Path to the Snyk CLI executable"},
	})
	registerFlag(fs, SettingAutomaticDownload, true, "Manage binaries automatically", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationRemoteKey:   {"automatic_download"},
		configresolver.AnnotationDisplayName: {"Automatic Download"},
		configresolver.AnnotationDescription: {"Automatically download and manage binaries"},
	})
	registerFlag(fs, SettingCliReleaseChannel, "", "CLI release channel", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationRemoteKey:   {"cli_release_channel"},
		configresolver.AnnotationDisplayName: {"CLI Release Channel"},
		configresolver.AnnotationDescription: {"Release channel for CLI updates"},
	})
	registerFlag(fs, SettingOrganization, "", "Default organization", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationDisplayName: {"Organization"},
		configresolver.AnnotationDescription: {"Default Snyk organization"},
	})
	registerFlag(fs, SettingAutomaticAuthentication, true, "Automatic authentication", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationDisplayName: {"Automatic Authentication"},
		configresolver.AnnotationDescription: {"Enable automatic authentication"},
	})
	registerFlag(fs, SettingCliInsecure, false, "Allow insecure CLI connections", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationDisplayName: {"CLI Insecure"},
		configresolver.AnnotationDescription: {"Allow insecure SSL connections for CLI"},
		configresolver.AnnotationWriteOnly:   {"true"},
	})
	registerFlag(fs, SettingFormat, "md", "Output format", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationDisplayName: {"Output Format"},
		configresolver.AnnotationDescription: {"Output format for scan results (html, plain)"},
	})
	registerFlag(fs, SettingDeviceId, "", "Device identifier", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationDisplayName: {"Device ID"},
		configresolver.AnnotationDescription: {"Unique device identifier for analytics"},
	})
	registerFlag(fs, SettingOffline, false, "Offline mode", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationDisplayName: {"Offline Mode"},
		configresolver.AnnotationDescription: {"Run in offline mode without network access"},
	})
	registerFlag(fs, SettingUserSettingsPath, "", "User settings PATH", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationDisplayName: {"User Settings Path"},
		configresolver.AnnotationDescription: {"User-specified PATH for shell environment"},
	})
	registerFlag(fs, SettingHoverVerbosity, 3, "Hover verbosity level", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationDisplayName: {"Hover Verbosity"},
		configresolver.AnnotationDescription: {"Verbosity level for hover information (0-3)"},
	})
	registerFlag(fs, SettingClientProtocolVersion, "", "Client protocol version", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationDisplayName: {"Client Protocol Version"},
		configresolver.AnnotationDescription: {"Required LSP protocol version from client"},
	})
	registerFlag(fs, SettingOsPlatform, "", "OS platform", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationDisplayName: {"OS Platform"},
		configresolver.AnnotationDescription: {"Operating system platform identifier"},
	})
	registerFlag(fs, SettingOsArch, "", "OS architecture", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationDisplayName: {"OS Architecture"},
		configresolver.AnnotationDescription: {"Operating system architecture"},
	})
	registerFlag(fs, SettingRuntimeName, "", "Runtime name", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationDisplayName: {"Runtime Name"},
		configresolver.AnnotationDescription: {"IDE runtime name"},
	})
	registerFlag(fs, SettingRuntimeVersion, "", "Runtime version", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationDisplayName: {"Runtime Version"},
		configresolver.AnnotationDescription: {"IDE runtime version"},
	})
	registerFlag(fs, SettingTrustedFolders, "", "Trusted folder paths (sent by IDEs)", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationDisplayName: {"Trusted Folders"},
		configresolver.AnnotationDescription: {"List of trusted folder paths"},
	})
	registerFlag(fs, SettingSecureAtInceptionExecutionFreq, "", "Secure at inception frequency", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationDisplayName: {"Secure At Inception Frequency"},
		configresolver.AnnotationDescription: {"When to run secure at inception scanning"},
	})

	// folder scope settings
	folderScope := string(configresolver.FolderScope)
	registerFlag(fs, SettingEnabledSeverities, "", "Enabled severity filter", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationRemoteKey:   {"severities"},
		configresolver.AnnotationDisplayName: {"Enabled Severities"},
		configresolver.AnnotationDescription: {"Severity filter for findings"},
	})
	registerFlag(fs, SettingRiskScoreThreshold, 0, "Risk score threshold (0-1000)", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationRemoteKey:   {"risk_score_threshold"},
		configresolver.AnnotationDisplayName: {"Risk Score Threshold"},
		configresolver.AnnotationDescription: {"Minimum risk score for findings (0-1000)"},
	})
	registerFlag(fs, SettingCweIds, "", "CWE IDs filter", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationRemoteKey:   {"cwe"},
		configresolver.AnnotationDisplayName: {"CWE IDs"},
		configresolver.AnnotationDescription: {"Comma-separated CWE IDs to filter"},
	})
	registerFlag(fs, SettingCveIds, "", "CVE IDs filter", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationRemoteKey:   {"cve"},
		configresolver.AnnotationDisplayName: {"CVE IDs"},
		configresolver.AnnotationDescription: {"Comma-separated CVE IDs to filter"},
	})
	registerFlag(fs, SettingRuleIds, "", "Rule IDs filter", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationRemoteKey:   {"rule"},
		configresolver.AnnotationDisplayName: {"Rule IDs"},
		configresolver.AnnotationDescription: {"Comma-separated rule IDs to filter"},
	})
	registerFlag(fs, SettingSnykCodeEnabled, false, "Enable Snyk Code", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationDisplayName: {"Snyk Code Enabled"},
		configresolver.AnnotationDescription: {"Enable Snyk Code security analysis"},
	})
	registerFlag(fs, SettingSnykOssEnabled, true, "Enable Snyk Open Source", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationDisplayName: {"Snyk OSS Enabled"},
		configresolver.AnnotationDescription: {"Enable Snyk Open Source analysis"},
	})
	registerFlag(fs, SettingSnykIacEnabled, true, "Enable Snyk IaC", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationDisplayName: {"Snyk IaC Enabled"},
		configresolver.AnnotationDescription: {"Enable Snyk Infrastructure as Code analysis"},
	})
	registerFlag(fs, SettingSnykSecretsEnabled, false, "Enable Snyk Secrets", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationDisplayName: {"Snyk Secrets Enabled"},
		configresolver.AnnotationDescription: {"Enable Snyk Secrets detection"},
	})
	registerFlag(fs, SettingScanAutomatic, true, "Automatic scan mode", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationRemoteKey:   {"automatic"},
		configresolver.AnnotationDisplayName: {"Scan Automatic"},
		configresolver.AnnotationDescription: {"Enable automatic scanning"},
	})
	registerFlag(fs, SettingScanNetNew, "", "Enable delta findings", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationRemoteKey:   {"net_new"},
		configresolver.AnnotationDisplayName: {"Scan Net New"},
		configresolver.AnnotationDescription: {"Enable net-new/delta findings"},
	})
	registerFlag(fs, SettingIssueViewOpenIssues, true, "Show open issues in view", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationRemoteKey:   {"open_issues"},
		configresolver.AnnotationDisplayName: {"Issue View Open Issues"},
		configresolver.AnnotationDescription: {"Show open issues in view"},
	})
	registerFlag(fs, SettingIssueViewIgnoredIssues, false, "Show ignored issues in view", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationRemoteKey:   {"ignored_issues"},
		configresolver.AnnotationDisplayName: {"Issue View Ignored Issues"},
		configresolver.AnnotationDescription: {"Show ignored issues in view"},
	})

	registerFlag(fs, SettingReferenceFolder, "", "Reference folder path", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationRemoteKey:   {"reference_folder"},
		configresolver.AnnotationDisplayName: {"Reference Folder"},
		configresolver.AnnotationDescription: {"Path to reference folder for baseline"},
	})
	registerFlag(fs, SettingReferenceBranch, "", "Reference branch for baseline", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationRemoteKey:   {"reference_branch"},
		configresolver.AnnotationDisplayName: {"Reference Branch"},
		configresolver.AnnotationDescription: {"Branch used as baseline for net-new findings"},
	})
	registerFlag(fs, SettingAdditionalParameters, "", "Additional CLI parameters", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationRemoteKey:   {"additional_parameters"},
		configresolver.AnnotationDisplayName: {"Additional Parameters"},
		configresolver.AnnotationDescription: {"Additional parameters passed to CLI"},
	})
	registerFlag(fs, SettingCliAdditionalOssParameters, "", "Additional OSS CLI parameters", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationDisplayName: {"CLI Additional OSS Parameters"},
		configresolver.AnnotationDescription: {"Additional parameters passed to the Snyk OSS CLI scanner"},
	})
	registerFlag(fs, SettingAdditionalEnvironment, "", "Additional environment variables", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationRemoteKey:   {"additional_environment"},
		configresolver.AnnotationDisplayName: {"Additional Environment"},
		configresolver.AnnotationDescription: {"Additional environment variables for CLI"},
	})
	registerFlag(fs, SettingBaseBranch, "", "Base branch for delta scanning", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationDisplayName: {"Base Branch"},
		configresolver.AnnotationDescription: {"Base branch for delta findings comparison"},
	})
	registerFlag(fs, SettingLocalBranches, "", "Local branches", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationDisplayName: {"Local Branches"},
		configresolver.AnnotationDescription: {"Available local branches (enriched by LS from git)"},
	})
	registerFlag(fs, SettingPreferredOrg, "", "Preferred organization for this folder", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationDisplayName: {"Preferred Organization"},
		configresolver.AnnotationDescription: {"Organization to use when operating on this folder"},
	})
	registerFlag(fs, SettingAutoDeterminedOrg, "", "Auto-determined organization", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationDisplayName: {"Auto-Determined Organization"},
		configresolver.AnnotationDescription: {"Organization automatically determined by LDX-Sync"},
	})
	registerFlag(fs, SettingOrgSetByUser, false, "Organization set by user", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationDisplayName: {"Organization Set By User"},
		configresolver.AnnotationDescription: {"Whether the user explicitly chose the organization"},
	})
	registerFlag(fs, SettingScanCommandConfig, "", "Scan command configuration", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationDisplayName: {"Scan Command Config"},
		configresolver.AnnotationDescription: {"Custom scan command configuration per product"},
	})
	registerFlag(fs, SettingSastSettings, "", "SAST settings from Snyk API", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationDisplayName: {"SAST Settings"},
		configresolver.AnnotationDescription: {"SAST configuration from Snyk API (autofix, local code engine)"},
	})

	registerFlag(fs, SettingSeverityFilterCritical, true, "Enable critical severity findings", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationDisplayName: {"Severity Filter Critical"},
		configresolver.AnnotationDescription: {"Include critical severity findings"},
	})
	registerFlag(fs, SettingSeverityFilterHigh, true, "Enable high severity findings", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationDisplayName: {"Severity Filter High"},
		configresolver.AnnotationDescription: {"Include high severity findings"},
	})
	registerFlag(fs, SettingSeverityFilterMedium, true, "Enable medium severity findings", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationDisplayName: {"Severity Filter Medium"},
		configresolver.AnnotationDescription: {"Include medium severity findings"},
	})
	registerFlag(fs, SettingSeverityFilterLow, true, "Enable low severity findings", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationDisplayName: {"Severity Filter Low"},
		configresolver.AnnotationDescription: {"Include low severity findings"},
	})
	registerFlag(fs, SettingSnykAdvisorEnabled, false, "Enable Snyk Advisor", map[string][]string{
		configresolver.AnnotationScope:       {folderScope},
		configresolver.AnnotationDisplayName: {"Snyk Advisor Enabled"},
		configresolver.AnnotationDescription: {"Enable Snyk Advisor recommendations"},
	})

	// Write-only settings (accepted IDE→LS, NOT sent LS→IDE)
	registerFlag(fs, SettingToken, "", "Authentication token", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationWriteOnly:   {"true"},
		configresolver.AnnotationDisplayName: {"Token"},
		configresolver.AnnotationDescription: {"Snyk authentication token"},
	})
	registerFlag(fs, SettingSendErrorReports, true, "Send error reports", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationWriteOnly:   {"true"},
		configresolver.AnnotationDisplayName: {"Send Error Reports"},
		configresolver.AnnotationDescription: {"Enable sending error reports to Snyk"},
	})
	registerFlag(fs, SettingEnableSnykLearnCodeActions, true, "Enable Snyk Learn code actions", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationWriteOnly:   {"true"},
		configresolver.AnnotationDisplayName: {"Snyk Learn Code Actions"},
		configresolver.AnnotationDescription: {"Enable Snyk Learn code actions"},
	})
	registerFlag(fs, SettingEnableSnykOssQuickFixActions, false, "Enable Snyk OSS quick fix code actions", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationWriteOnly:   {"true"},
		configresolver.AnnotationDisplayName: {"Snyk OSS Quick Fix Code Actions"},
		configresolver.AnnotationDescription: {"Enable Snyk OSS quick fix code actions"},
	})
	registerFlag(fs, SettingEnableSnykOpenBrowserActions, false, "Enable Snyk open browser actions", map[string][]string{
		configresolver.AnnotationScope:       {machineScope},
		configresolver.AnnotationWriteOnly:   {"true"},
		configresolver.AnnotationDisplayName: {"Snyk Open Browser Actions"},
		configresolver.AnnotationDescription: {"Enable Snyk open browser actions"},
	})
}

// GetSettingScope returns the configresolver.Scope for the named setting by reading the
// AnnotationScope annotation from the registered flagset metadata. Returns FolderScope
// when fm is nil or the setting has no scope annotation.
func GetSettingScope(fm workflow.ConfigurationOptionsMetaData, name string) configresolver.Scope {
	if fm != nil {
		if val, ok := fm.GetConfigurationOptionAnnotation(name, configresolver.AnnotationScope); ok {
			return configresolver.Scope(val)
		}
	}
	return configresolver.FolderScope
}

// IsMachineWideSetting returns true if the setting is machine-scoped.
func IsMachineWideSetting(fm workflow.ConfigurationOptionsMetaData, name string) bool {
	return GetSettingScope(fm, name) == configresolver.MachineScope
}

// IsFolderScopedSetting returns true if the setting is folder-scoped (i.e. not machine-scoped).
func IsFolderScopedSetting(fm workflow.ConfigurationOptionsMetaData, name string) bool {
	return GetSettingScope(fm, name) == configresolver.FolderScope
}

// IsWriteOnlySetting returns true if the setting is write-only (accepted IDE→LS, not sent LS→IDE).
func IsWriteOnlySetting(fm workflow.ConfigurationOptionsMetaData, name string) bool {
	if fm == nil {
		return false
	}
	val, ok := fm.GetConfigurationOptionAnnotation(name, configresolver.AnnotationWriteOnly)
	return ok && val == "true"
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
