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

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// newTrustCommand builds a trustWorkspaceFoldersCommand wired to the test engine.
// Note: no notifier field — Execute sends trust notifications via ws.TrustFoldersAndScan,
// which uses the workspace's own notifier; this command has no need for one.
func newTrustCommand(engine workflow.Engine, args ...any) *trustWorkspaceFoldersCommand {
	return &trustWorkspaceFoldersCommand{
		command:        types.CommandData{CommandId: types.TrustWorkspaceFoldersCommand, Arguments: args},
		engine:         engine,
		configResolver: testutil.DefaultConfigResolver(engine),
	}
}

func TestTrustWorkspaceFolders_PerFolder_TrustsOnlyGivenFolder(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), true)

	f1 := types.PathKey("folder-one")
	f2 := types.PathKey("folder-two")
	setupToggleWorkspaceFolders(t, engine, f1, f2)

	cmd := newTrustCommand(engine, string(f1))
	_, err := cmd.Execute(t.Context())
	require.NoError(t, err)

	trusted := types.GetGlobalSliceFilePath(conf, types.SettingTrustedFolders)
	assert.Contains(t, trusted, f1, "the requested folder should be trusted")
	assert.NotContains(t, trusted, f2, "other untrusted folders must be left alone")
}

func TestTrustWorkspaceFolders_NoArg_TrustsAllUntrusted(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), true)

	f1 := types.PathKey("folder-one")
	f2 := types.PathKey("folder-two")
	setupToggleWorkspaceFolders(t, engine, f1, f2)

	cmd := newTrustCommand(engine)
	_, err := cmd.Execute(t.Context())
	require.NoError(t, err)

	trusted := types.GetGlobalSliceFilePath(conf, types.SettingTrustedFolders)
	assert.Contains(t, trusted, f1)
	assert.Contains(t, trusted, f2)
}

func TestTrustWorkspaceFolders_UnknownPath_TrustsNothing(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), true)

	f1 := types.PathKey("folder-one")
	setupToggleWorkspaceFolders(t, engine, f1)

	cmd := newTrustCommand(engine, "/not/a/workspace/folder")
	_, err := cmd.Execute(t.Context())
	require.NoError(t, err)

	trusted := types.GetGlobalSliceFilePath(conf, types.SettingTrustedFolders)
	assert.NotContains(t, trusted, f1, "an unmatched folder-path arg must not trust any folder")
}

func TestTrustWorkspaceFolders_TrustDisabled_NoOp(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), false)

	f1 := types.PathKey("folder-one")
	setupToggleWorkspaceFolders(t, engine, f1)

	cmd := newTrustCommand(engine)
	_, err := cmd.Execute(t.Context())
	require.NoError(t, err)

	trusted := types.GetGlobalSliceFilePath(conf, types.SettingTrustedFolders)
	assert.Empty(t, trusted, "with trust disabled the command must do nothing")
}
