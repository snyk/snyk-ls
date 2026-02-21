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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/types"
)

func TestOssIssueData_GetPackageName_ReturnsPackageName(t *testing.T) {
	data := OssIssueData{PackageName: "ch.qos.logback:logback-core"}
	assert.Equal(t, "ch.qos.logback:logback-core", data.GetPackageName())
}

func TestOssIssueData_GetVersion_ReturnsVersion(t *testing.T) {
	data := OssIssueData{Version: "1.3.14"}
	assert.Equal(t, "1.3.14", data.GetVersion())
}

func TestCodeIssueData_GetPackageName_ReturnsEmpty(t *testing.T) {
	data := CodeIssueData{Title: "Hardcoded Secret"}
	assert.Equal(t, "", data.GetPackageName())
}

func TestCodeIssueData_GetVersion_ReturnsEmpty(t *testing.T) {
	data := CodeIssueData{Title: "Hardcoded Secret"}
	assert.Equal(t, "", data.GetVersion())
}

func TestIaCIssueData_GetPackageName_ReturnsEmpty(t *testing.T) {
	data := IaCIssueData{Title: "Container is running in privileged mode"}
	assert.Equal(t, "", data.GetPackageName())
}

func TestIaCIssueData_GetVersion_ReturnsEmpty(t *testing.T) {
	data := IaCIssueData{Title: "Container is running in privileged mode"}
	assert.Equal(t, "", data.GetVersion())
}

// Verify all three types satisfy the IssueAdditionalData interface.
func TestIssueAdditionalData_InterfaceCompliance(t *testing.T) {
	var _ types.IssueAdditionalData = OssIssueData{}
	var _ types.IssueAdditionalData = CodeIssueData{}
	var _ types.IssueAdditionalData = IaCIssueData{}
}
