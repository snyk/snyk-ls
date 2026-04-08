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

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"

	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestToggleTreeFilter_Execute_SeverityHigh_Disabled(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingSeverityFilterCritical), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSeverityFilterHigh), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSeverityFilterMedium), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSeverityFilterLow), true)

	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{"severity", "high", false},
		},
		engine: engine,
	}

	result, err := cmd.Execute(t.Context())
	require.NoError(t, err)
	assert.Nil(t, result, "toggleTreeFilter should return nil; tree HTML is pushed via notification")

	assert.True(t, types.GetGlobalBool(engine.GetConfiguration(), types.SettingSeverityFilterCritical))
	assert.False(t, types.GetGlobalBool(engine.GetConfiguration(), types.SettingSeverityFilterHigh), "high should be disabled")
	assert.True(t, types.GetGlobalBool(engine.GetConfiguration(), types.SettingSeverityFilterMedium))
	assert.True(t, types.GetGlobalBool(engine.GetConfiguration(), types.SettingSeverityFilterLow))
}

func TestToggleTreeFilter_Execute_SeverityMedium_Enabled(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingSeverityFilterCritical), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSeverityFilterHigh), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSeverityFilterMedium), false)
	conf.Set(configresolver.UserGlobalKey(types.SettingSeverityFilterLow), true)

	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{"severity", "medium", true},
		},
		engine: engine,
	}

	result, err := cmd.Execute(t.Context())
	require.NoError(t, err)
	assert.Nil(t, result, "toggleTreeFilter should return nil; tree HTML is pushed via notification")

	assert.True(t, types.GetGlobalBool(engine.GetConfiguration(), types.SettingSeverityFilterMedium), "medium should be enabled")
}

func TestToggleTreeFilter_Execute_IssueViewOpenIssues_Disabled(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingIssueViewOpenIssues), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingIssueViewIgnoredIssues), true)

	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{"issueView", "openIssues", false},
		},
		engine: engine,
	}

	result, err := cmd.Execute(t.Context())
	require.NoError(t, err)
	assert.Nil(t, result, "toggleTreeFilter should return nil; tree HTML is pushed via notification")

	assert.False(t, types.GetGlobalBool(conf, types.SettingIssueViewOpenIssues), "open issues should be disabled")
	assert.True(t, types.GetGlobalBool(conf, types.SettingIssueViewIgnoredIssues))
}

func TestToggleTreeFilter_Execute_IssueViewIgnoredIssues_Enabled(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingIssueViewOpenIssues), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingIssueViewIgnoredIssues), false)

	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{"issueView", "ignoredIssues", true},
		},
		engine: engine,
	}

	result, err := cmd.Execute(t.Context())
	require.NoError(t, err)
	assert.Nil(t, result, "toggleTreeFilter should return nil; tree HTML is pushed via notification")

	assert.True(t, types.GetGlobalBool(conf, types.SettingIssueViewIgnoredIssues), "ignored issues should be enabled")
}

func TestToggleTreeFilter_Execute_MissingArgs_ReturnsError(t *testing.T) {
	engine := testutil.UnitTest(t)
	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{},
		},
		engine: engine,
	}

	_, err := cmd.Execute(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected 3 arguments")
}

func TestToggleTreeFilter_Execute_InvalidFilterType_ReturnsError(t *testing.T) {
	engine := testutil.UnitTest(t)
	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{"unknown", "high", true},
		},
		engine: engine,
	}

	_, err := cmd.Execute(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown filter type")
}

func TestToggleTreeFilter_Execute_InvalidSeverityValue_ReturnsError(t *testing.T) {
	engine := testutil.UnitTest(t)
	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{"severity", "extreme", true},
		},
		engine: engine,
	}

	_, err := cmd.Execute(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown severity value")
}

func TestToggleTreeFilter_Execute_ReturnsNil_NotHtml(t *testing.T) {
	engine := testutil.UnitTest(t)
	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{"severity", "low", false},
		},
		engine: engine,
	}

	result, err := cmd.Execute(t.Context())
	require.NoError(t, err)
	assert.Nil(t, result, "toggleTreeFilter should return nil; tree HTML is pushed via $/snyk.treeView notification")
}

func TestToggleTreeFilter_Command_ReturnsCommandData(t *testing.T) {
	cmdData := types.CommandData{CommandId: types.ToggleTreeFilter}
	cmd := &toggleTreeFilter{command: cmdData}
	assert.Equal(t, cmdData, cmd.Command())
}
