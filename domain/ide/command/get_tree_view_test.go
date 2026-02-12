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

func TestGetTreeViewCommand_Execute_ReturnsHtml(t *testing.T) {
	c := testutil.UnitTest(t)
	cmd := &getTreeViewCommand{
		command: types.CommandData{CommandId: types.GetTreeViewCommand},
		c:       c,
	}

	result, err := cmd.Execute(t.Context())
	require.NoError(t, err)

	htmlResult, ok := result.(string)
	require.True(t, ok, "result should be a string")
	assert.Contains(t, htmlResult, "<!DOCTYPE html>")
	assert.Contains(t, htmlResult, "${ideScript}")
}

func TestGetTreeViewCommand_Command_ReturnsCommandData(t *testing.T) {
	cmdData := types.CommandData{CommandId: types.GetTreeViewCommand}
	cmd := &getTreeViewCommand{
		command: cmdData,
	}

	assert.Equal(t, cmdData, cmd.Command())
}
