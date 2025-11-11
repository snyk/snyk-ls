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

// Package cli_test contains integration tests for the CLI infrastructure components.
// These tests use testutil.SmokeTest() for comprehensive setup and verify end-to-end behavior,
// including interactions between multiple folders with different organizations.
// For unit tests with single folder scenarios, see cli_extension_executor_test.go in the cli package.
package cli_test

import (
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// Test_SnykCli_GetCommand_UsesFolderOrganization verifies that getCommand() adds
// the correct --org flag based on FolderOrganization() for different folders.
func Test_SnykCli_GetCommand_UsesFolderOrganization(t *testing.T) {
	c := testutil.SmokeTest(t, false)
	ctx := t.Context()

	er := error_reporting.NewTestErrorReporter()
	notifier := notification.NewMockNotifier()
	cliExecutor := cli.NewExecutor(c, er, notifier).(*cli.SnykCli)

	// Set up two folders with different orgs
	folderPath1 := types.FilePath(t.TempDir())
	folderPath2 := types.FilePath(t.TempDir())

	globalOrg := "00000000-0000-0000-0000-000000000001"
	folderOrg1 := "00000000-0000-0000-0000-000000000002"
	folderOrg2 := "00000000-0000-0000-0000-000000000003"

	// Set a global org that is different from folder orgs
	c.SetOrganization(globalOrg)

	// Configure folder 1 with its own org
	folderConfig1 := &types.FolderConfig{
		FolderPath:                  folderPath1,
		PreferredOrg:                folderOrg1,
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}
	err := storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), folderConfig1, c.Logger())
	require.NoError(t, err)

	// Configure folder 2 with a different org
	folderConfig2 := &types.FolderConfig{
		FolderPath:                  folderPath2,
		PreferredOrg:                folderOrg2,
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}
	err = storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), folderConfig2, c.Logger())
	require.NoError(t, err)

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
	c := testutil.SmokeTest(t, false)
	ctx := t.Context()

	er := error_reporting.NewTestErrorReporter()
	notifier := notification.NewMockNotifier()
	cliExecutor := cli.NewExecutor(c, er, notifier).(*cli.SnykCli)

	folderPath := types.FilePath(t.TempDir())
	const folderOrg = "folder-org-replacement"
	const existingOrg = "existing-org"

	// Configure folder with its own org
	folderConfig := &types.FolderConfig{
		FolderPath:                  folderPath,
		PreferredOrg:                folderOrg,
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}
	err := storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), folderConfig, c.Logger())
	require.NoError(t, err)

	// Test with a command that already has an --org flag
	baseCmd := []string{"snyk", "test", "--json", "--org=" + existingOrg}
	command, err := cliExecutor.GetCommandForTesting(ctx, baseCmd, folderPath)
	require.NoError(t, err)
	require.NotNil(t, command)

	// Verify the existing --org flag was replaced with folder org
	foundOrg := false
	orgCount := 0
	for _, arg := range command.Args {
		if strings.HasPrefix(arg, "--org=") {
			orgValue := strings.TrimPrefix(arg, "--org=")
			assert.Equal(t, folderOrg, orgValue, "Existing --org flag should be replaced with folder org")
			foundOrg = true
			orgCount++
		}
	}
	assert.True(t, foundOrg, "Command should contain --org flag with folder org")
	assert.Equal(t, 1, orgCount, "Command should contain exactly one --org flag")
}

// Test_ExtensionExecutor_DoExecute_UsesFolderOrganization is an INTEGRATION TEST that verifies
// ExtensionExecutor.doExecute() sets the correct org in legacyCLIConfig based on FolderOrganization()
// for multiple different folders. This test uses testutil.SmokeTest() for comprehensive setup.
// For unit tests with single folder scenarios, see cli_extension_executor_test.go
func Test_ExtensionExecutor_DoExecute_UsesFolderOrganization(t *testing.T) {
	c := testutil.SmokeTest(t, false)

	// Set up two folders with different orgs
	folderPath1 := types.FilePath(t.TempDir())
	folderPath2 := types.FilePath(t.TempDir())

	globalOrg := "00000000-0000-0000-0000-000000000001"
	folderOrg1 := "00000000-0000-0000-0000-000000000002"
	folderOrg2 := "00000000-0000-0000-0000-000000000003"

	// Set a global org that is different from folder orgs
	c.SetOrganization(globalOrg)

	// Configure folder 1 with its own org
	folderConfig1 := &types.FolderConfig{
		FolderPath:                  folderPath1,
		PreferredOrg:                folderOrg1,
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}
	err := storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), folderConfig1, c.Logger())
	require.NoError(t, err)

	// Configure folder 2 with a different org
	folderConfig2 := &types.FolderConfig{
		FolderPath:                  folderPath2,
		PreferredOrg:                folderOrg2,
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}
	err = storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), folderConfig2, c.Logger())
	require.NoError(t, err)

	// Test folder 1: verify doExecute() sets org in config
	cmd1 := []string{"snyk", "test"}
	capturedOrg1, _ := executeAndCaptureConfig(t, c, cmd1, folderPath1)
	assert.Equal(t, folderOrg1, capturedOrg1, "ExtensionExecutor should use folder1's org in config")

	// Test folder 2: verify doExecute() sets different org in config
	cmd2 := []string{"snyk", "test"}
	capturedOrg2, _ := executeAndCaptureConfig(t, c, cmd2, folderPath2)
	assert.Equal(t, folderOrg2, capturedOrg2, "ExtensionExecutor should use folder2's org in config")

	// Verify the orgs are different
	assert.NotEqual(t, folderOrg1, folderOrg2, "Folder orgs should be different")
}

// Test_ExtensionExecutor_DoExecute_FallsBackToGlobalOrg is an INTEGRATION TEST that verifies
// ExtensionExecutor.doExecute() falls back to global org when no folder-specific org is configured.
// This test uses testutil.SmokeTest() for comprehensive setup.
// For unit tests with single folder scenarios, see cli_extension_executor_test.go
func Test_ExtensionExecutor_DoExecute_FallsBackToGlobalOrg(t *testing.T) {
	c := testutil.SmokeTest(t, false)

	folderPath := types.FilePath(t.TempDir())
	const globalOrg = "00000000-0000-0000-0000-000000000004"

	// Set only global org, no folder-specific org
	c.SetOrganization(globalOrg)

	// Test: verify doExecute() uses global org as fallback
	cmd := []string{"snyk", "test"}
	capturedOrg, _ := executeAndCaptureConfig(t, c, cmd, folderPath)
	assert.Equal(t, globalOrg, capturedOrg, "ExtensionExecutor should fall back to global org when no folder org is set")
}

// executeAndCaptureConfig is a helper function for INTEGRATION TESTS that executes ExtensionExecutor
// and captures the organization and working directory values passed to the workflow.
// This captures the actual config values passed to the workflow to verify folder-specific org usage.
func executeAndCaptureConfig(t *testing.T, c *config.Config, cmd []string, workingDir types.FilePath) (capturedOrg interface{}, capturedWorkingDir string) {
	t.Helper()

	workflowId := workflow.NewWorkflowIdentifier("legacycli")
	engine := c.Engine()
	_, err := engine.Register(workflowId, workflow.ConfigurationOptionsFromFlagset(&pflag.FlagSet{}), func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
		gafConf := invocation.GetConfiguration()
		// Get the raw value without triggering resolution
		capturedOrg = gafConf.GetString(configuration.ORGANIZATION)
		capturedWorkingDir = gafConf.GetString(configuration.WORKING_DIRECTORY)
		data := workflow.NewData(workflow.NewTypeIdentifier(workflowId, "testdata"), "txt", []byte("test"))
		return []workflow.Data{data}, nil
	})
	require.NoError(t, err)

	executor := cli.NewExtensionExecutor(c)
	_, err = executor.Execute(t.Context(), cmd, workingDir)
	require.NoError(t, err)

	return capturedOrg, capturedWorkingDir
}
