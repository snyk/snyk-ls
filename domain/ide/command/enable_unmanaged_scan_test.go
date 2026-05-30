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
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestEnableUnmanagedScan_Execute(t *testing.T) {
	const folder types.FilePath = "/repo/cpp-project"

	t.Run("sets snyk_oss_unmanaged_enabled=true for the folder", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		resolver := testutil.DefaultConfigResolver(engine)
		fc := &types.FolderConfig{FolderPath: folder, ConfigResolver: resolver}

		assert.False(t, resolver.GetBool(types.SettingSnykOssUnmanagedEnabled, fc),
			"precondition: setting should default to false")

		cmd := &enableUnmanagedScan{
			command: types.CommandData{
				CommandId: types.EnableUnmanagedScanCommand,
				Arguments: []any{string(folder)},
			},
			engine: engine,
		}

		result, err := cmd.Execute(context.Background())
		require.NoError(t, err)
		assert.Equal(t, true, result)

		assert.True(t, resolver.GetBool(types.SettingSnykOssUnmanagedEnabled, fc))
	})

	t.Run("returns error on missing folder path", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		cmd := &enableUnmanagedScan{
			command: types.CommandData{CommandId: types.EnableUnmanagedScanCommand},
			engine:  engine,
		}
		_, err := cmd.Execute(context.Background())
		require.Error(t, err)
	})

	t.Run("returns error on non-string folder path", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		cmd := &enableUnmanagedScan{
			command: types.CommandData{
				CommandId: types.EnableUnmanagedScanCommand,
				Arguments: []any{42},
			},
			engine: engine,
		}
		_, err := cmd.Execute(context.Background())
		require.Error(t, err)
	})
}
