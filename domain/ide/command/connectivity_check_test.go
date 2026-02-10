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

package command

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	connectivityworkflow "github.com/snyk/go-application-framework/pkg/local_workflows/connectivity_check_extension"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_connectivityCheckCommand_Command(t *testing.T) {
	c := testutil.UnitTest(t)

	cut := connectivityCheckCommand{
		command: types.CommandData{
			Title:     "Connectivity Check",
			CommandId: types.ConnectivityCheckCommand,
			Arguments: []any{},
		},
		c: c,
	}

	cmd := cut.Command()
	assert.Equal(t, types.ConnectivityCheckCommand, cmd.CommandId)
	assert.Equal(t, "Connectivity Check", cmd.Title)
}

func Test_connectivityCheckCommand_Execute_returnsFormattedText(t *testing.T) {
	c := testutil.UnitTest(t)

	// Mock the workflow invocation
	mockEngine, _ := testutil.SetUpEngineMock(t, c)
	expectedOutput := "Mock connectivity checking...\n\n✓ All fake checks passed"
	mockWorkflowData := []workflow.Data{
		workflow.NewData(
			workflow.NewTypeIdentifier(connectivityworkflow.WORKFLOWID_CONNECTIVITY_CHECK, "connectivity-check"),
			"text/plain",
			[]byte(expectedOutput),
		),
	}
	mockEngine.EXPECT().
		InvokeWithConfig(connectivityworkflow.WORKFLOWID_CONNECTIVITY_CHECK, gomock.Any()).
		Return(mockWorkflowData, nil).
		Times(1)

	// Setup the command
	cut := connectivityCheckCommand{
		command: types.CommandData{
			Title:     "Connectivity Check",
			CommandId: types.ConnectivityCheckCommand,
			Arguments: []any{},
		},
		c: c,
	}

	// Act
	response, err := cut.Execute(t.Context())
	require.NoError(t, err)

	// Assert
	responseStr, ok := response.(string)
	require.True(t, ok, "Response should be a string")
	assert.Equal(t, expectedOutput, responseStr)
}

func Test_connectivityCheckCommand_Execute_integration(t *testing.T) {
	c := testutil.IntegTest(t)

	cut := connectivityCheckCommand{
		command: types.CommandData{
			Title:     "Connectivity Check",
			CommandId: types.ConnectivityCheckCommand,
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

	// Verify it contains expected connectivity check output
	assert.Contains(t, responseStr, "Checking for proxy configuration")
	assert.Contains(t, responseStr, "Testing connectivity to Snyk endpoints")
	assert.Contains(t, responseStr, "api.snyk.io                    OK (HTTP 204)")
	assert.Contains(t, responseStr, "Authentication token is configured")
	assert.Contains(t, responseStr, "Snyk Token and Organizations")
}
