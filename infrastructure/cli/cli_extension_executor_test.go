/*
 * © 2023 Snyk Limited All rights reserved.
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
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/app"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_ExecuteLegacyCLI_SUCCESS(t *testing.T) {
	c := testutil.UnitTest(t)

	// Prepare
	cmd := []string{"snyk", "test"}
	expectedSnykCommand := cmd[1:]
	actualSnykCommand := []string{}

	expectedWorkingDir := types.FilePath("my work dir")
	actualWorkingDir := ""

	expectedPayload := []byte("hello")

	workflowId := workflow.NewWorkflowIdentifier("legacycli")
	engine := app.CreateAppEngine()
	_, err := engine.Register(workflowId, workflow.ConfigurationOptionsFromFlagset(&pflag.FlagSet{}), func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
		gafConf := invocation.GetConfiguration()
		actualSnykCommand = gafConf.GetStringSlice(configuration.RAW_CMD_ARGS)
		actualWorkingDir = gafConf.GetString(configuration.WORKING_DIRECTORY)
		data := workflow.NewData(workflow.NewTypeIdentifier(workflowId, "testdata"), "txt", expectedPayload)
		return []workflow.Data{data}, nil
	})
	assert.Nil(t, err)

	err = engine.Init()
	assert.Nil(t, err)

	c.SetEngine(engine)

	// Run
	executorUnderTest := NewExtensionExecutor(c)
	actualData, err := executorUnderTest.Execute(t.Context(), cmd, expectedWorkingDir)
	assert.Nil(t, err)

	// Compare
	assert.Equal(t, expectedPayload, actualData)
	assert.Equal(t, expectedSnykCommand, actualSnykCommand)
	assert.Equal(t, string(expectedWorkingDir), actualWorkingDir)
}

func Test_ExecuteLegacyCLI_FAILED(t *testing.T) {
	c := testutil.UnitTest(t)

	// Prepare
	engine := app.CreateAppEngine()
	c.SetEngine(engine)
	cmd := []string{"snyk", "test"}
	expectedPayload := []byte{}

	// Run
	executorUnderTest := NewExtensionExecutor(c)
	actualData, err := executorUnderTest.Execute(t.Context(), cmd, "")

	// Compare
	assert.NotNil(t, err)
	assert.Equal(t, expectedPayload, actualData)
}

func Test_ExtensionExecutor_LoadsConfigFiles(t *testing.T) {
	c := testutil.UnitTest(t)
	originalPathValue := "original_path" + pathListSep + "in_both_path"
	t.Setenv("PATH", originalPathValue)
	t.Setenv("TEST_VAR", "overrideable_value")

	// Create a temporary directory with a config file
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, ".snyk.env")
	configPathValue := "config" + pathListSep + "in_both_path"
	configContent := []byte("PATH=" + configPathValue + "\nTEST_VAR=test_value\n")
	err := os.WriteFile(configFile, configContent, 0660)
	require.NoError(t, err)

	// Prepare a simple workflow for the legacycli
	workflowId := workflow.NewWorkflowIdentifier("legacycli")
	engine := c.Engine()
	_, err = engine.Register(workflowId, workflow.ConfigurationOptionsFromFlagset(&pflag.FlagSet{}), func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
		data := workflow.NewData(workflow.NewTypeIdentifier(workflowId, "testdata"), "txt", []byte("test"))
		return []workflow.Data{data}, nil
	})
	require.NoError(t, err)

	engine.GetConfiguration().Set(configuration.CUSTOM_CONFIG_FILES, []string{configFile})

	// Execute the extension executor which should load config files
	executorUnderTest := NewExtensionExecutor(c)
	_, err = executorUnderTest.Execute(t.Context(), []string{"snyk", "fake-cmd-for-testing"}, types.FilePath(tempDir))
	require.NoError(t, err)

	// Verify environment variable was loaded from config file
	assert.Equal(t, "test_value", os.Getenv("TEST_VAR"))

	// Verify PATH was prepended (config path should come first)
	expectedPath := "config" + pathListSep + "in_both_path" + pathListSep + "original_path" // "in_both_path" is deduplicated, only "original_path" remains from original PATH
	assert.Equal(t, expectedPath, os.Getenv("PATH"),
		"PATH should be config path prepended with deduplication applied")
}

func Test_ExtensionExecutor_WaitsForEnvReadiness(t *testing.T) {
	c := testutil.UnitTest(t)

	// Create a test-controlled environment readiness channel
	testPrepareDefaultEnvChannel := make(chan bool)
	testPrepareDefaultEnvChannelClose := sync.OnceFunc(func() { close(testPrepareDefaultEnvChannel) })
	t.Cleanup(testPrepareDefaultEnvChannelClose)

	// Replace the ready channel with our test channel to simulate "not ready" state
	configValue := reflect.ValueOf(c).Elem()
	channelField := configValue.FieldByName("prepareDefaultEnvChannel")
	channelField = reflect.NewAt(channelField.Type(), unsafe.Pointer(channelField.UnsafeAddr())).Elem()
	channelField.Set(reflect.ValueOf(testPrepareDefaultEnvChannel))

	// Set up workflow engine for extension executor
	workflowId := workflow.NewWorkflowIdentifier("legacycli")
	engine := c.Engine()
	_, err := engine.Register(workflowId, workflow.ConfigurationOptionsFromFlagset(&pflag.FlagSet{}), func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
		data := workflow.NewData(workflow.NewTypeIdentifier(workflowId, "testdata"), "txt", []byte("test"))
		return []workflow.Data{data}, nil
	})
	require.NoError(t, err)

	engine.GetConfiguration().Set(configuration.CUSTOM_CONFIG_FILES, []string{})

	executor := NewExtensionExecutor(c)

	// Start execution in a separate goroutine; it should block waiting on readiness
	started := make(chan bool, 1)
	t.Cleanup(func() { close(started) })
	unblocked := make(chan bool, 1)
	t.Cleanup(func() { close(unblocked) })
	var result []byte
	var execErr error
	go func() {
		started <- true
		result, execErr = executor.Execute(t.Context(), []string{"snyk", "fake-cmd-for-testing"}, types.FilePath(t.TempDir()))
		unblocked <- true
	}()

	// Wait until goroutine starts
	require.Eventually(t, func() bool {
		select {
		case <-started:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)

	// Verify it's blocked - should not complete for a reasonable time
	require.Never(t, func() bool {
		select {
		case <-unblocked:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond, "Execute should block until environment is ready")

	// Now close the test channel to signal readiness
	testPrepareDefaultEnvChannelClose()

	// Verify it unblocks and completes
	require.Eventually(t, func() bool {
		select {
		case <-unblocked:
			return true
		default:
			return false
		}
	}, 2*time.Second, 10*time.Millisecond, "Execute should complete after environment becomes ready")

	require.NoError(t, execErr)
	assert.NotNil(t, result)
}

// Helper function to execute ExtensionExecutor and capture organization and working directory
func executeAndCaptureConfig(t *testing.T, c *config.Config, cmd []string, workingDir types.FilePath) (capturedOrg interface{}, capturedWorkingDir string) {
	t.Helper()

	workflowId := workflow.NewWorkflowIdentifier("legacycli")
	engine := c.Engine()
	_, err := engine.Register(workflowId, workflow.ConfigurationOptionsFromFlagset(&pflag.FlagSet{}), func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
		gafConf := invocation.GetConfiguration()
		// Get the raw value without triggering resolution
		capturedOrg = gafConf.Get(configuration.ORGANIZATION)
		capturedWorkingDir = gafConf.GetString(configuration.WORKING_DIRECTORY)
		data := workflow.NewData(workflow.NewTypeIdentifier(workflowId, "testdata"), "txt", []byte("test"))
		return []workflow.Data{data}, nil
	})
	require.NoError(t, err)

	executor := NewExtensionExecutor(c)
	_, err = executor.Execute(t.Context(), cmd, workingDir)
	require.NoError(t, err)

	return capturedOrg, capturedWorkingDir
}

func Test_ExtensionExecutor_SetsFolderLevelOrganization(t *testing.T) {
	c := testutil.UnitTest(t)

	folderPath := types.FilePath(t.TempDir())

	// Set global org as a UUID (no API resolution needed)
	globalOrgUUID := "00000000-0000-0000-0000-000000000001"
	c.Engine().GetConfiguration().Set(configuration.ORGANIZATION, globalOrgUUID)

	// Create and store folder config with specific org UUID
	folderOrgUUID := "00000000-0000-0000-0000-000000000002"
	storedCfg := &types.FolderConfig{
		FolderPath:                  folderPath,
		Organization:                folderOrgUUID,
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}
	err := storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), storedCfg, c.Logger())
	require.NoError(t, err)

	// Test
	capturedOrg, _ := executeAndCaptureConfig(t, c, []string{"snyk", "test"}, folderPath)

	// Verify we are using the folder-specific organization
	assert.Equal(t, folderOrgUUID, capturedOrg, "Should use folder-specific organization")
}

func Test_ExtensionExecutor_UsesGlobalOrgWhenNoFolderOrg(t *testing.T) {
	c := testutil.UnitTest(t)

	folderPath := types.FilePath(t.TempDir())

	// Set only global org (UUID to avoid API resolution), no folder-specific org
	globalOrgUUID := "00000000-0000-0000-0000-000000000001"
	c.Engine().GetConfiguration().Set(configuration.ORGANIZATION, globalOrgUUID)

	// Test
	capturedOrg, _ := executeAndCaptureConfig(t, c, []string{"snyk", "test"}, folderPath)

	// Verify global org was used as fallback (since no folder-specific org exists)
	assert.Equal(t, globalOrgUUID, capturedOrg, "Should fall back to global organization")
}

func Test_ExtensionExecutor_HandlesEmptyWorkingDir(t *testing.T) {
	c := testutil.UnitTest(t)

	// Set global org as UUID
	globalOrgUUID := "00000000-0000-0000-0000-000000000001"
	c.Engine().GetConfiguration().Set(configuration.ORGANIZATION, globalOrgUUID)

	// Test
	capturedOrg, capturedWorkingDir := executeAndCaptureConfig(t, c, []string{"snyk", "version"}, "")

	// Verify working dir was empty and global org was used
	assert.Empty(t, capturedWorkingDir, "Working directory should be empty")
	assert.Equal(t, globalOrgUUID, capturedOrg, "Should use global org for empty workingDir")
}
