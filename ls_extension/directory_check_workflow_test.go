/*
 * © 2026 Snyk Limited All rights reserved.
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

package ls_extension

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/app"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_IDEDirectoryCheckWorkflow_TextOutput(t *testing.T) {
	testutil.UnitTest(t)

	engine := app.CreateAppEngineWithOptions()

	err := Init(engine)
	require.NoError(t, err)

	err = engine.Init()
	require.NoError(t, err)

	engineConfig := configuration.NewWithOpts(
		configuration.WithAutomaticEnv(),
	)

	data, err := engine.InvokeWithConfig(WORKFLOWID_IDE_DIRECTORY_CHECK, engineConfig)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Verify we got text output with expected content
	output := string(data[0].GetPayload().([]byte))
	assert.Contains(t, output, "IDE Directory Diagnostics", "Should contain diagnostics title")
	assert.Contains(t, output, "Current User", "Should contain current user section")
	assert.Contains(t, output, "Directory", "Should contain directory results")
	assert.Equal(t, "text/plain", data[0].GetContentType())
}

func Test_IDEDirectoryCheckWorkflow_JSONOutput(t *testing.T) {
	testutil.UnitTest(t)

	engine := app.CreateAppEngineWithOptions()

	err := Init(engine)
	require.NoError(t, err)

	err = engine.Init()
	require.NoError(t, err)

	engineConfig := configuration.NewWithOpts(
		configuration.WithAutomaticEnv(),
	)
	engineConfig.Set("json", true)

	data, err := engine.InvokeWithConfig(WORKFLOWID_IDE_DIRECTORY_CHECK, engineConfig)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Verify we got JSON output
	output := string(data[0].GetPayload().([]byte))
	assert.Contains(t, output, `"currentUser"`, "Should contain currentUser JSON field")
	assert.Contains(t, output, `"directoryResults"`, "Should contain directoryResults JSON field")
	assert.Equal(t, "application/json", data[0].GetContentType())
}

func Test_IDEDirectoryCheckWorkflow_NoColour(t *testing.T) {
	testutil.UnitTest(t)

	engine := app.CreateAppEngineWithOptions()

	err := Init(engine)
	require.NoError(t, err)

	err = engine.Init()
	require.NoError(t, err)

	engineConfig := configuration.NewWithOpts(
		configuration.WithAutomaticEnv(),
	)
	engineConfig.Set("no-color", true)

	data, err := engine.InvokeWithConfig(WORKFLOWID_IDE_DIRECTORY_CHECK, engineConfig)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Verify we got text output (no-color just disables ANSI codes)
	output := string(data[0].GetPayload().([]byte))
	assert.Contains(t, output, "IDE Directory Diagnostics", "Should contain diagnostics title")
	assert.Equal(t, "text/plain", data[0].GetContentType())
}
