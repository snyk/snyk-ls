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

package snyk

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/types"
)

func TestOssIssueData_GetFileIcon_KnownPM_ReturnsInlineSVG(t *testing.T) {
	data := OssIssueData{PackageManager: "npm"}
	icon := data.GetFileIcon("/path/to/package.json")
	assert.NotEmpty(t, icon)
	assert.Contains(t, icon, "<svg", "expected inline SVG for known package manager")
}

func TestOssIssueData_GetFileIcon_UnknownPM_ReturnsOSIcon(t *testing.T) {
	data := OssIssueData{PackageManager: "unknown-pm"}
	icon := data.GetFileIcon("/path/to/package.json")
	assert.NotEmpty(t, icon)
	assert.True(t,
		strings.Contains(icon, "<svg") || strings.Contains(icon, "<img"),
		"expected HTML icon fragment for unknown package manager",
	)
}

func TestCodeIssueData_GetFileIcon_ReturnsOSIcon(t *testing.T) {
	data := CodeIssueData{Title: "Hardcoded Secret"}
	icon := data.GetFileIcon("/path/to/main.go")
	assert.NotEmpty(t, icon)
	assert.True(t,
		strings.Contains(icon, "<svg") || strings.Contains(icon, "<img"),
		"expected HTML icon fragment for code issue",
	)
}

func TestIaCIssueData_GetFileIcon_ReturnsOSIcon(t *testing.T) {
	data := IaCIssueData{Title: "Misconfiguration"}
	icon := data.GetFileIcon("/path/to/main.tf")
	assert.NotEmpty(t, icon)
	assert.True(t,
		strings.Contains(icon, "<svg") || strings.Contains(icon, "<img"),
		"expected HTML icon fragment for IaC issue",
	)
}

func TestSecretsIssueData_GetFileIcon_ReturnsOSIcon(t *testing.T) {
	data := SecretsIssueData{Title: "Exposed secret"}
	icon := data.GetFileIcon("/path/to/.env")
	assert.NotEmpty(t, icon)
	assert.True(t,
		strings.Contains(icon, "<svg") || strings.Contains(icon, "<img"),
		"expected HTML icon fragment for secrets issue",
	)
}

// Verify all types satisfy the IssueAdditionalData interface.
func TestIssueAdditionalData_InterfaceCompliance(t *testing.T) {
	var _ types.IssueAdditionalData = OssIssueData{}
	var _ types.IssueAdditionalData = CodeIssueData{}
	var _ types.IssueAdditionalData = IaCIssueData{}
	var _ types.IssueAdditionalData = SecretsIssueData{}
}
