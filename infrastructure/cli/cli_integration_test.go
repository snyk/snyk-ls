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

package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_ExtensionExecutor_DoExecute_UsesFolderOrganization(t *testing.T) {
	c := testutil.IntegTest(t)

	// Set up two folders with different orgs
	folderPath1, folderPath2, _, folderOrg1, folderOrg2 := testutil.SetupFoldersWithOrgs(t, c)

	// Test folder 1: verify doExecute() sets org in config
	executor := NewExtensionExecutor(c)
	cmd1 := []string{"snyk", "test"}
	capturedOrg1, _ := testutil.ExecuteAndCaptureConfig(t, c, executor, cmd1, folderPath1)
	assert.Equal(t, folderOrg1, capturedOrg1, "ExtensionExecutor should use folder1's org in config")

	// Test folder 2: verify doExecute() sets different org in config
	cmd2 := []string{"snyk", "test"}
	capturedOrg2, _ := testutil.ExecuteAndCaptureConfig(t, c, executor, cmd2, folderPath2)
	assert.Equal(t, folderOrg2, capturedOrg2, "ExtensionExecutor should use folder2's org in config")

	// Verify the orgs are different
	assert.NotEqual(t, folderOrg1, folderOrg2, "Folder orgs should be different")
}

func Test_ExtensionExecutor_DoExecute_FallsBackToGlobalOrg(t *testing.T) {
	c := testutil.IntegTest(t)

	folderPath, globalOrg := testutil.SetupGlobalOrgOnly(t, c)

	// Test: verify doExecute() uses global org as fallback
	executor := NewExtensionExecutor(c)
	cmd := []string{"snyk", "test"}
	capturedOrg, _ := testutil.ExecuteAndCaptureConfig(t, c, executor, cmd, folderPath)
	assert.Equal(t, globalOrg, capturedOrg, "ExtensionExecutor should fall back to global org when no folder org is set")
}
