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

package testutil

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	"github.com/subosito/gotenv"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
)

// CLIExecutor is a minimal interface for executing CLI commands in tests.
// This allows the test helper to work with any executor implementation.
type CLIExecutor interface {
	Execute(ctx context.Context, cmd []string, workingDir types.FilePath, env gotenv.Env) (resp []byte, err error)
}

// ExecuteAndCaptureConfig executes a CLI command using the provided executor and captures
// the organization and working directory from the workflow configuration.
// This is useful for testing that the correct organization is set based on folder configuration.
func ExecuteAndCaptureConfig(t *testing.T, c *config.Config, executor CLIExecutor, cmd []string, workingDir types.FilePath) (capturedOrg interface{}, capturedWorkingDir string) {
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

	env := gotenv.Env{}
	for _, kv := range os.Environ() {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		env[k] = v
	}
	_, err = executor.Execute(t.Context(), cmd, workingDir, env)
	require.NoError(t, err)

	return capturedOrg, capturedWorkingDir
}
