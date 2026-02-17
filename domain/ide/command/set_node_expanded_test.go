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

	"github.com/snyk/snyk-ls/domain/ide/treeview"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestSetNodeExpanded_Execute_SetsExpanded(t *testing.T) {
	es := treeview.NewExpandState()
	cmd := &setNodeExpanded{
		command: types.CommandData{
			CommandId: types.SetNodeExpanded,
			Arguments: []any{"product:/project:Snyk Code", true},
		},
		expandState: es,
	}

	result, err := cmd.Execute(t.Context())
	require.NoError(t, err)
	assert.Nil(t, result)

	expanded, ok := es.Get("product:/project:Snyk Code")
	assert.True(t, ok)
	assert.True(t, expanded)
}

func TestSetNodeExpanded_Execute_SetsCollapsed(t *testing.T) {
	es := treeview.NewExpandState()
	cmd := &setNodeExpanded{
		command: types.CommandData{
			CommandId: types.SetNodeExpanded,
			Arguments: []any{"folder:/project-a", false},
		},
		expandState: es,
	}

	result, err := cmd.Execute(t.Context())
	require.NoError(t, err)
	assert.Nil(t, result)

	expanded, ok := es.Get("folder:/project-a")
	assert.True(t, ok)
	assert.False(t, expanded)
}

func TestSetNodeExpanded_Execute_MissingArgs_ReturnsError(t *testing.T) {
	es := treeview.NewExpandState()
	cmd := &setNodeExpanded{
		command: types.CommandData{
			CommandId: types.SetNodeExpanded,
			Arguments: []any{},
		},
		expandState: es,
	}

	_, err := cmd.Execute(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected 2 arguments")
}

func TestSetNodeExpanded_Command_ReturnsCommandData(t *testing.T) {
	cmdData := types.CommandData{CommandId: types.SetNodeExpanded}
	cmd := &setNodeExpanded{command: cmdData, expandState: treeview.NewExpandState()}
	assert.Equal(t, cmdData, cmd.Command())
}
