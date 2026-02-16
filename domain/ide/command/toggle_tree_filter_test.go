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
	"github.com/snyk/snyk-ls/internal/util"
)

func TestToggleTreeFilter_Execute_SeverityHigh_Disabled(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetSeverityFilter(util.Ptr(types.NewSeverityFilter(true, true, true, true)))

	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{"severity", "high", false},
		},
		c: c,
	}

	result, err := cmd.Execute(t.Context())
	require.NoError(t, err)
	assert.NotNil(t, result)

	filter := c.FilterSeverity()
	assert.True(t, filter.Critical)
	assert.False(t, filter.High, "high should be disabled")
	assert.True(t, filter.Medium)
	assert.True(t, filter.Low)
}

func TestToggleTreeFilter_Execute_SeverityMedium_Enabled(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetSeverityFilter(util.Ptr(types.NewSeverityFilter(true, true, false, true)))

	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{"severity", "medium", true},
		},
		c: c,
	}

	result, err := cmd.Execute(t.Context())
	require.NoError(t, err)
	assert.NotNil(t, result)

	filter := c.FilterSeverity()
	assert.True(t, filter.Medium, "medium should be enabled")
}

func TestToggleTreeFilter_Execute_IssueViewOpenIssues_Disabled(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetIssueViewOptions(util.Ptr(types.NewIssueViewOptions(true, true)))

	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{"issueView", "openIssues", false},
		},
		c: c,
	}

	result, err := cmd.Execute(t.Context())
	require.NoError(t, err)
	assert.NotNil(t, result)

	options := c.IssueViewOptions()
	assert.False(t, options.OpenIssues, "open issues should be disabled")
	assert.True(t, options.IgnoredIssues)
}

func TestToggleTreeFilter_Execute_IssueViewIgnoredIssues_Enabled(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetIssueViewOptions(util.Ptr(types.NewIssueViewOptions(true, false)))

	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{"issueView", "ignoredIssues", true},
		},
		c: c,
	}

	result, err := cmd.Execute(t.Context())
	require.NoError(t, err)
	assert.NotNil(t, result)

	options := c.IssueViewOptions()
	assert.True(t, options.IgnoredIssues, "ignored issues should be enabled")
}

func TestToggleTreeFilter_Execute_MissingArgs_ReturnsError(t *testing.T) {
	c := testutil.UnitTest(t)
	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{},
		},
		c: c,
	}

	_, err := cmd.Execute(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected 3 arguments")
}

func TestToggleTreeFilter_Execute_InvalidFilterType_ReturnsError(t *testing.T) {
	c := testutil.UnitTest(t)
	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{"unknown", "high", true},
		},
		c: c,
	}

	_, err := cmd.Execute(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown filter type")
}

func TestToggleTreeFilter_Execute_InvalidSeverityValue_ReturnsError(t *testing.T) {
	c := testutil.UnitTest(t)
	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{"severity", "extreme", true},
		},
		c: c,
	}

	_, err := cmd.Execute(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown severity value")
}

func TestToggleTreeFilter_Execute_ReturnsTreeViewHtml(t *testing.T) {
	c := testutil.UnitTest(t)
	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{"severity", "low", false},
		},
		c: c,
	}

	result, err := cmd.Execute(t.Context())
	require.NoError(t, err)

	htmlResult, ok := result.(string)
	require.True(t, ok, "result should be a string")
	assert.Contains(t, htmlResult, "<!DOCTYPE html>")
}

func TestToggleTreeFilter_Command_ReturnsCommandData(t *testing.T) {
	cmdData := types.CommandData{CommandId: types.ToggleTreeFilter}
	cmd := &toggleTreeFilter{command: cmdData}
	assert.Equal(t, cmdData, cmd.Command())
}
