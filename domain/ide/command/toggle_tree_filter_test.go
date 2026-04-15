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

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

func TestToggleTreeFilter_Execute_SeverityHigh_Disabled(t *testing.T) {
	engine := testutil.UnitTest(t)
	resolver := testutil.ConfigResolverForTest(engine)
	config.SetSeverityFilterOnConfig(engine.GetConfiguration(), util.Ptr(types.NewSeverityFilter(true, true, true, true)), engine.GetLogger(), resolver)

	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{"severity", "high", false},
		},
		engine:         engine,
		configResolver: resolver,
	}

	result, err := cmd.Execute(t.Context())
	require.NoError(t, err)
	assert.Nil(t, result, "toggleTreeFilter should return nil; tree HTML is pushed via notification")

	filter := config.GetFilterSeverity(engine.GetConfiguration())
	assert.True(t, filter.Critical)
	assert.False(t, filter.High, "high should be disabled")
	assert.True(t, filter.Medium)
	assert.True(t, filter.Low)
}

func TestToggleTreeFilter_Execute_SeverityMedium_Enabled(t *testing.T) {
	engine := testutil.UnitTest(t)
	resolver := testutil.ConfigResolverForTest(engine)
	config.SetSeverityFilterOnConfig(engine.GetConfiguration(), util.Ptr(types.NewSeverityFilter(true, true, false, true)), engine.GetLogger(), resolver)

	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{"severity", "medium", true},
		},
		engine:         engine,
		configResolver: resolver,
	}

	result, err := cmd.Execute(t.Context())
	require.NoError(t, err)
	assert.Nil(t, result, "toggleTreeFilter should return nil; tree HTML is pushed via notification")

	filter := config.GetFilterSeverity(engine.GetConfiguration())
	assert.True(t, filter.Medium, "medium should be enabled")
}

func TestToggleTreeFilter_Execute_IssueViewOpenIssues_Disabled(t *testing.T) {
	engine := testutil.UnitTest(t)
	resolver := testutil.ConfigResolverForTest(engine)
	config.SetIssueViewOptionsOnConfig(engine.GetConfiguration(), util.Ptr(types.NewIssueViewOptions(true, true)), engine.GetLogger(), resolver)

	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{"issueView", "openIssues", false},
		},
		engine:         engine,
		configResolver: resolver,
	}

	result, err := cmd.Execute(t.Context())
	require.NoError(t, err)
	assert.Nil(t, result, "toggleTreeFilter should return nil; tree HTML is pushed via notification")

	options := config.GetIssueViewOptions(engine.GetConfiguration())
	assert.False(t, options.OpenIssues, "open issues should be disabled")
	assert.True(t, options.IgnoredIssues)
}

func TestToggleTreeFilter_Execute_IssueViewIgnoredIssues_Enabled(t *testing.T) {
	engine := testutil.UnitTest(t)
	resolver := testutil.ConfigResolverForTest(engine)
	config.SetIssueViewOptionsOnConfig(engine.GetConfiguration(), util.Ptr(types.NewIssueViewOptions(true, false)), engine.GetLogger(), resolver)

	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{"issueView", "ignoredIssues", true},
		},
		engine:         engine,
		configResolver: resolver,
	}

	result, err := cmd.Execute(t.Context())
	require.NoError(t, err)
	assert.Nil(t, result, "toggleTreeFilter should return nil; tree HTML is pushed via notification")

	options := config.GetIssueViewOptions(engine.GetConfiguration())
	assert.True(t, options.IgnoredIssues, "ignored issues should be enabled")
}

func TestToggleTreeFilter_Execute_MissingArgs_ReturnsError(t *testing.T) {
	engine := testutil.UnitTest(t)
	resolver := testutil.ConfigResolverForTest(engine)
	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{},
		},
		engine:         engine,
		configResolver: resolver,
	}

	_, err := cmd.Execute(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected 3 arguments")
}

func TestToggleTreeFilter_Execute_InvalidFilterType_ReturnsError(t *testing.T) {
	engine := testutil.UnitTest(t)
	resolver := testutil.ConfigResolverForTest(engine)
	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{"unknown", "high", true},
		},
		engine:         engine,
		configResolver: resolver,
	}

	_, err := cmd.Execute(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown filter type")
}

func TestToggleTreeFilter_Execute_InvalidSeverityValue_ReturnsError(t *testing.T) {
	engine := testutil.UnitTest(t)
	resolver := testutil.ConfigResolverForTest(engine)
	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{"severity", "extreme", true},
		},
		engine:         engine,
		configResolver: resolver,
	}

	_, err := cmd.Execute(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown severity value")
}

func TestToggleTreeFilter_Execute_ReturnsNil_NotHtml(t *testing.T) {
	engine := testutil.UnitTest(t)
	resolver := testutil.ConfigResolverForTest(engine)
	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{"severity", "low", false},
		},
		engine:         engine,
		configResolver: resolver,
	}

	result, err := cmd.Execute(t.Context())
	require.NoError(t, err)
	assert.Nil(t, result, "toggleTreeFilter should return nil; tree HTML is pushed via $/snyk.treeView notification")
}

func TestToggleTreeFilter_Command_ReturnsCommandData(t *testing.T) {
	resolver := testutil.ConfigResolverForTest(testutil.UnitTest(t))
	cmdData := types.CommandData{CommandId: types.ToggleTreeFilter}
	cmd := &toggleTreeFilter{command: cmdData, configResolver: resolver}
	assert.Equal(t, cmdData, cmd.Command())
}
