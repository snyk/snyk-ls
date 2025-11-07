/*
 * © 2025 Snyk Limited
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

package constants

// Snyk API Endpoints
const (
	// SNYK_API_URL is the default Snyk API endpoint
	SNYK_API_URL = "https://api.snyk.io"
	// SNYK_UI_URL is the default Snyk web application endpoint
	SNYK_UI_URL = "https://app.snyk.io"
	// SNYK_DEEPROXY_API_URL is the default Snyk Code API endpoint
	SNYK_DEEPROXY_API_URL = "https://deeproxy.snyk.io"
)

// Regional Snyk API Endpoints
const (
	// SNYK_API_EU_URL is the EU Snyk API endpoint
	SNYK_API_EU_URL = "https://api.eu.snyk.io"
	// SNYK_UI_EU_URL is the EU Snyk web application endpoint
	SNYK_UI_EU_URL = "https://app.eu.snyk.io"
	// SNYK_API_US_URL is the US Snyk API endpoint
	SNYK_API_US_URL = "https://api.us.snyk.io"
	// SNYK_UI_US_URL is the US Snyk web application endpoint
	SNYK_UI_US_URL = "https://app.us.snyk.io"
	// SNYK_API_FEDRAMP_URL is the FedRAMP Snyk API endpoint
	SNYK_API_FEDRAMP_URL = "https://api.fedramp.snykgov.io"
	// SNYK_UI_FEDRAMP_URL is the FedRAMP Snyk web application endpoint
	SNYK_UI_FEDRAMP_URL = "https://app.fedramp.snykgov.io"
)

// Download Endpoints
const (
	// SNYK_CLI_DOWNLOAD_BASE_URL is the base URL for downloading Snyk CLI
	SNYK_CLI_DOWNLOAD_BASE_URL = "https://downloads.snyk.io"
	// SNYK_LS_DOWNLOAD_BASE_URL is the base URL for downloading Snyk Language Server
	SNYK_LS_DOWNLOAD_BASE_URL = "https://static.snyk.io/snyk-ls"
	// GITHUB_CLI_RELEASES_URL is the GitHub releases page for Snyk CLI
	GITHUB_CLI_RELEASES_URL = "https://github.com/snyk/cli/releases"
	// GITHUB_LS_RELEASES_URL is the GitHub releases page for Snyk Language Server
	GITHUB_LS_RELEASES_URL = "https://github.com/snyk/snyk-ls/releases"
	// GITHUB_API_BASE_URL is the base URL for GitHub API
	GITHUB_API_BASE_URL = "https://api.github.com"
)

// Documentation and Learning Resources
const (
	// SNYK_DOCS_CODE_RULES_URL is the URL for Snyk Code security rules documentation
	SNYK_DOCS_CODE_RULES_URL = "https://docs.snyk.io/scan-using-snyk/snyk-code/snyk-code-security-rules"
	// SNYK_LEARN_LICENSE_URL is the URL for Snyk Learn license policy management lesson
	SNYK_LEARN_LICENSE_URL = "https://learn.snyk.io/lesson/license-policy-management/?loc=ide"
)

// External Vulnerability Databases
//
//nolint:misspell // MITRE is the correct name of the organization, not a typo
const (
	// CVE_MITRE_BASE_URL is the base URL for CVE details on MITRE
	CVE_MITRE_BASE_URL = "https://cve.mitre.org/cgi-bin/cvename.cgi"
	// CWE_MITRE_BASE_URL is the base URL for CWE details on MITRE
	CWE_MITRE_BASE_URL = "https://cwe.mitre.org/data/definitions"
	// SNYK_VULN_DB_BASE_URL is the base URL for Snyk vulnerability database
	SNYK_VULN_DB_BASE_URL = "https://snyk.io/vuln"
)
