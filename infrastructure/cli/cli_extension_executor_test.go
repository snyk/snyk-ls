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
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/app"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

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
	originalPath := "original:existing"
	t.Setenv("PATH", originalPath)
	t.Setenv("TEST_VAR", "overrideable_value")

	// Create a temporary directory with a config file
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, ".snyk.env")
	configContent := []byte("PATH=config:file\nTEST_VAR=test_value\n")
	err := os.WriteFile(configFile, configContent, 0660)
	assert.NoError(t, err)

	// Prepare a workflow that can verify environment loading
	workflowId := workflow.NewWorkflowIdentifier("legacycli")
	engine := app.CreateAppEngine()
	actualEnvVar := ""
	actualPath := ""

	_, err = engine.Register(workflowId, workflow.ConfigurationOptionsFromFlagset(&pflag.FlagSet{}), func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
		// Capture environment state during workflow execution
		actualEnvVar = os.Getenv("TEST_VAR")
		actualPath = os.Getenv("PATH")
		data := workflow.NewData(workflow.NewTypeIdentifier(workflowId, "testdata"), "txt", []byte("test"))
		return []workflow.Data{data}, nil
	})
	assert.NoError(t, err)

	err = engine.Init()
	assert.NoError(t, err)

	config.CurrentConfig().SetEngine(engine)
	engine.GetConfiguration().Set(configuration.CUSTOM_CONFIG_FILES, []string{configFile})

	// Execute the extension executor which should loads config files
	executorUnderTest := NewExtensionExecutor(c)
	_, err = executorUnderTest.Execute(t.Context(), []string{"snyk", "test"}, types.FilePath(tempDir))
	assert.NoError(t, err)

	// Verify environment variable was loaded from config file
	assert.Equal(t, "test_value", actualEnvVar)

	// Verify PATH was prepended (config path should come first)
	expectedPath := "config:file:" + originalPath // "config:file:original:existing"
	assert.Equal(t, expectedPath, actualPath,
		"PATH should be config path prepended to original path")
}
