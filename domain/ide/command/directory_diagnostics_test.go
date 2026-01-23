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

package command

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_directoryDiagnosticsCommand_Command(t *testing.T) {
	c := testutil.UnitTest(t)

	cut := directoryDiagnosticsCommand{
		command: types.CommandData{
			Title:     "Directory Diagnostics",
			CommandId: types.DirectoryDiagnosticsCommand,
			Arguments: []any{},
		},
		c: c,
	}

	cmd := cut.Command()
	assert.Equal(t, types.DirectoryDiagnosticsCommand, cmd.CommandId)
	assert.Equal(t, "Directory Diagnostics", cmd.Title)
}

func Test_directoryDiagnosticsCommand_Execute_returnsFormattedText(t *testing.T) {
	c := testutil.UnitTest(t)

	cut := directoryDiagnosticsCommand{
		command: types.CommandData{
			Title:     "Directory Diagnostics",
			CommandId: types.DirectoryDiagnosticsCommand,
			Arguments: []any{},
		},
		c: c,
	}

	response, err := cut.Execute(t.Context())
	require.NoError(t, err)

	// Verify response is a string
	responseStr, ok := response.(string)
	require.True(t, ok, "Response should be a string")
	require.NotEmpty(t, responseStr)

	// Verify it contains expected diagnostics output (plain text, no color)
	assert.Contains(t, responseStr, "IDE Directory Diagnostics")
	assert.Contains(t, responseStr, "Current User")
	assert.Contains(t, responseStr, "Directory")
}

func Test_directoryDiagnosticsCommand_Execute_withAdditionalDirs(t *testing.T) {
	c := testutil.UnitTest(t)

	tempDir := t.TempDir()

	cut := directoryDiagnosticsCommand{
		command: types.CommandData{
			Title:     "Directory Diagnostics",
			CommandId: types.DirectoryDiagnosticsCommand,
			Arguments: []any{
				[]any{
					map[string]any{
						"pathWanted":    tempDir,
						"purpose":       "Test Directory",
						"mayContainCLI": false,
					},
				},
			},
		},
		c: c,
	}

	response, err := cut.Execute(t.Context())
	require.NoError(t, err)

	responseStr, ok := response.(string)
	require.True(t, ok, "Response should be a string")

	// Should include both default directories and our custom one
	assert.Contains(t, responseStr, "IDE Directory Diagnostics")
	assert.Contains(t, responseStr, tempDir)
	assert.Contains(t, responseStr, "Test Directory")
}

func Test_directoryDiagnosticsCommand_Execute_includesConfiguredCLIPath(t *testing.T) {
	c := testutil.UnitTest(t)

	// Create a temp directory and set it as the CLI path
	tempDir := t.TempDir()
	cliPath := tempDir + "/snyk-cli"
	c.CliSettings().SetPath(cliPath)

	cut := directoryDiagnosticsCommand{
		command: types.CommandData{
			Title:     "Directory Diagnostics",
			CommandId: types.DirectoryDiagnosticsCommand,
			Arguments: []any{},
		},
		c: c,
	}

	response, err := cut.Execute(t.Context())
	require.NoError(t, err)

	responseStr, ok := response.(string)
	require.True(t, ok, "Response should be a string")

	// Should include the configured CLI path directory
	assert.Contains(t, responseStr, "IDE Directory Diagnostics")
	assert.Contains(t, responseStr, tempDir)
	assert.Contains(t, responseStr, "Configured CLI Path")
}
