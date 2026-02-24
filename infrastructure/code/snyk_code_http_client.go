/*
 * © 2022-2024 Snyk Limited
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

package code

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
)

const (
	completeStatus     = "COMPLETE"
	codeDescriptionURL = "https://docs.snyk.io/scan-using-snyk/snyk-code/snyk-code-security-rules"
)

var (
	issueSeverities = map[string]types.Severity{
		"3":       types.High,
		"2":       types.Medium,
		"warning": types.Medium, // Sarif Level
		"error":   types.High,   // Sarif Level
	}
)

var deeproxyRegex = regexp.MustCompile(`^(deeproxy\.)?`)

func issueSeverity(snykSeverity string) types.Severity {
	sev, ok := issueSeverities[snykSeverity]
	if !ok {
		return types.Low
	}
	return sev
}

// GetCodeApiUrlForFolder returns the Snyk Code API URL for the given folder.
// The folder parameter can be a subdirectory or file path; this function will find the workspace folder containing it.
// The URL is determined in the following order:
//   - If local code engine (SCLE) is enabled in the folder's SAST settings, we use the local engine endpoint
//   - If a custom endpoint from the folder's SAST settings is configured, we use the custom endpoint
//   - In non-FedRAMP environments, we return these as is
//   - In FedRAMP environments, the folder's organization is included in the URL path
//
// Returns an error if:
//   - folder is empty
//   - no workspace folder can be found for the given path
//   - in FedRAMP, if no organization can be determined for the folder
func GetCodeApiUrlForFolder(c *config.Config, folder types.FilePath) (string, error) {
	if folder == "" {
		return "", fmt.Errorf("no folder specified when trying to determine Snyk Code API URL")
	}

	folderConfig, err := c.FolderConfigForSubPath(folder)
	if err != nil {
		return "", err
	}

	return getCodeApiUrlFromFolderConfig(c, folderConfig)
}

// getCodeApiUrlFromFolderConfig returns the Code API URL using the provided folderConfig directly.
// This is useful for base branch scans where the folder path is a temporary directory.
func getCodeApiUrlFromFolderConfig(c *config.Config, folderConfig *types.FolderConfig) (string, error) {
	var endpoint string
	var err error
	if isLocalEngineEnabled(folderConfig.SastSettings) {
		endpoint = updateCodeApiLocalEngine(c, folderConfig.SastSettings)
	} else {
		endpoint, err = c.GetCodeApiUrlFromCustomEndpoint(folderConfig.SastSettings)
		if err != nil {
			return "", err
		}
	}

	if !c.IsFedramp() {
		return endpoint, nil
	}

	// We should not have SCLE in FedRAMP, but this code may still run and it should work even with SCLE
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}

	u.Host = deeproxyRegex.ReplaceAllString(u.Host, "api.")
	if !strings.HasPrefix(u.Host, "api.") {
		u.Host = "api." + u.Host
	}
	u.RawQuery = ""
	u.Fragment = ""

	// Get organization directly from folderConfig for FedRAMP
	org := c.FolderConfigOrganization(folderConfig)
	if org == "" {
		return "", fmt.Errorf("organization is required in a fedramp environment")
	}

	u.Path = "/hidden/orgs/" + org + "/code"

	return u.String(), nil
}
