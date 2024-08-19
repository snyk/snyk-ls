/*
 * © 2024 Snyk Limited
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
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cli2 "github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_executeCLI_callsCli(t *testing.T) {
	c := testutil.UnitTest(t)
	expected := `{ "outputKey": "outputValue" }`
	dir := t.TempDir()

	cli := cli2.NewTestExecutorWithResponse(expected)

	args := []any{dir, "iac", "test", "--json"}
	cut := executeCLICommand{
		command: types.CommandData{
			Title:     "testCMD",
			CommandId: types.ExecuteCLICommand,
			Arguments: args,
		},
		logger: c.Logger(),
		cli:    cli,
	}

	response, err := cut.Execute(context.Background())
	require.NoError(t, err)

	assert.True(t, cli.WasExecuted())
	assert.IsType(t, cliScanResult{}, response)
	assert.Equal(t, expected, response.(cliScanResult).StdOut)
}
