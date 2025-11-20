/*
 * © 2022 Snyk Limited All rights reserved.
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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testutil"
)

// Test_SnykCli_GetCommand_UsesFolderOrganization is an INTEGRATION TEST that verifies
// getCommand() adds the correct --org flag based on FolderOrganization() for different folders.
// This test uses testutil.IntegTest() to run in the integration test suite.
func Test_SnykCli_GetCommand_UsesFolderOrganization(t *testing.T) {
	c := testutil.IntegTest(t)
	ctx := t.Context()

	er := error_reporting.NewTestErrorReporter()
	notifier := notification.NewMockNotifier()
	cliExecutor := NewExecutor(c, er, notifier).(*SnykCli)

	// Set up two folders with different orgs
	folderPath1, folderPath2, _, folderOrg1, folderOrg2 := testutil.SetupFoldersWithOrgs(t, c)

	// Test folder 1: verify getCommand() adds --org flag with folder org
	baseCmd := []string{"snyk", "test", "--json"}
	command1, err := cliExecutor.GetCommandForTesting(ctx, baseCmd, folderPath1)
	require.NoError(t, err)
	require.NotNil(t, command1)

	// Verify the command includes --org flag with folder1's org
	foundOrg1 := false
	for _, arg := range command1.Args {
		if strings.HasPrefix(arg, "--org=") {
			orgValue := strings.TrimPrefix(arg, "--org=")
			assert.Equal(t, folderOrg1, orgValue, "Folder 1 should use its own org")
			foundOrg1 = true
			break
		}
	}
	assert.True(t, foundOrg1, "Command for folder 1 should contain --org flag with folder org")

	// Test folder 2: verify getCommand() adds --org flag with different folder org
	command2, err := cliExecutor.GetCommandForTesting(ctx, baseCmd, folderPath2)
	require.NoError(t, err)
	require.NotNil(t, command2)

	// Verify the command includes --org flag with folder2's org
	foundOrg2 := false
	for _, arg := range command2.Args {
		if strings.HasPrefix(arg, "--org=") {
			orgValue := strings.TrimPrefix(arg, "--org=")
			assert.Equal(t, folderOrg2, orgValue, "Folder 2 should use its own org")
			foundOrg2 = true
			break
		}
	}
	assert.True(t, foundOrg2, "Command for folder 2 should contain --org flag with folder org")

	// Verify the orgs are different
	assert.NotEqual(t, folderOrg1, folderOrg2, "Folder orgs should be different")
}

// Test_SnykCli_GetCommand_ReplacesExistingOrgFlag verifies that getCommand() replaces
// an existing --org flag with the folder-specific org.
func Test_SnykCli_GetCommand_ReplacesExistingOrgFlag(t *testing.T) {
	c := testutil.IntegTest(t)
	ctx := t.Context()

	er := error_reporting.NewTestErrorReporter()
	notifier := notification.NewMockNotifier()
	cliExecutor := NewExecutor(c, er, notifier).(*SnykCli)

	const folderOrg = "folder-org-replacement"
	const existingOrg = "existing-org"

	folderPath := testutil.SetupFolderWithOrg(t, c, folderOrg)

	// Test with a command that already has an --org flag
	baseCmd := []string{"snyk", "test", "--json", "--org=" + existingOrg}
	command, err := cliExecutor.GetCommandForTesting(ctx, baseCmd, folderPath)
	require.NoError(t, err)
	require.NotNil(t, command)

	// Verify the existing --org flag was replaced with folder org
	orgCount := 0
	for _, arg := range command.Args {
		if strings.HasPrefix(arg, "--org=") {
			orgValue := strings.TrimPrefix(arg, "--org=")
			assert.Equal(t, folderOrg, orgValue, "Existing --org flag should be replaced with folder org")
			orgCount++
		}
	}
	assert.Equal(t, 1, orgCount, "Command should contain exactly one --org flag")
}

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
