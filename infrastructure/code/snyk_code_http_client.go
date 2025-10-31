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
	"errors"
	"fmt"
	"net/url"
	"regexp"

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

var codeApiRegex = regexp.MustCompile(`^(deeproxy\.)?`)

func issueSeverity(snykSeverity string) types.Severity {
	sev, ok := issueSeverities[snykSeverity]
	if !ok {
		return types.Low
	}
	return sev
}

// GetCodeApiUrlForFolder returns the code API URL. In FedRAMP, it uses the organization from the given folder.
// The folder parameter can be a subdirectory; this function will find the workspace folder containing it.
func GetCodeApiUrlForFolder(c *config.Config, folder types.FilePath) (string, error) {
	if !c.IsFedramp() {
		return c.SnykCodeApi(), nil
	}
	if folder == "" {
		return "", fmt.Errorf("folder is required in a fedramp environment")
	}

	u, err := url.Parse(c.SnykCodeApi())
	if err != nil {
		return "", err
	}

	u.Host = codeApiRegex.ReplaceAllString(u.Host, "api.")

	workspaceFolder := c.Workspace().GetFolderContaining(folder)
	if workspaceFolder == nil {
		return "", fmt.Errorf("no workspace folder found for path: %s", folder)
	}
	org := c.FolderOrganization(workspaceFolder.Path())

	if org == "" {
		return "", errors.New("organization is required in a fedramp environment")
	}

	u.Path = "/hidden/orgs/" + org + "/code"

	return u.String(), nil
}
