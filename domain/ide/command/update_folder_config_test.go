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

func TestUpdateFolderConfig_SetBaseBranch_UpdatesConfig(t *testing.T) {
	c := testutil.UnitTest(t)

	folderPath := types.FilePath("/test/project")
	cmd := &updateFolderConfig{
		command: types.CommandData{
			Arguments: []any{
				string(folderPath),
				map[string]any{"baseBranch": "develop"},
			},
		},
		c: c,
	}

	result, err := cmd.Execute(context.Background())
	require.NoError(t, err)
	assert.Equal(t, true, result)

	fc := c.FolderConfig(folderPath)
	require.NotNil(t, fc)
	assert.Equal(t, "develop", fc.BaseBranch)
}

func TestUpdateFolderConfig_MissingArgs_ReturnsError(t *testing.T) {
	c := testutil.UnitTest(t)

	cmd := &updateFolderConfig{
		command: types.CommandData{
			Arguments: []any{},
		},
		c: c,
	}

	_, err := cmd.Execute(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected 2 arguments")
}

func TestUpdateFolderConfig_EmptyFolderPath_ReturnsError(t *testing.T) {
	c := testutil.UnitTest(t)

	cmd := &updateFolderConfig{
		command: types.CommandData{
			Arguments: []any{
				"",
				map[string]any{"baseBranch": "develop"},
			},
		},
		c: c,
	}

	_, err := cmd.Execute(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty folder path")
}

func TestUpdateFolderConfig_SetBaseBranch_ClearsReferenceFolderPath(t *testing.T) {
	c := testutil.UnitTest(t)

	folderPath := types.FilePath(t.TempDir())
	refDir := types.FilePath(t.TempDir())

	fc := c.FolderConfig(folderPath)
	fc.ReferenceFolderPath = refDir
	_ = c.UpdateFolderConfig(fc)

	cmd := &updateFolderConfig{
		command: types.CommandData{
			Arguments: []any{
				string(folderPath),
				map[string]any{"baseBranch": "develop"},
			},
		},
		c: c,
	}

	_, err := cmd.Execute(context.Background())
	require.NoError(t, err)

	fc = c.FolderConfig(folderPath)
	assert.Equal(t, "develop", fc.BaseBranch)
	assert.Empty(t, fc.ReferenceFolderPath, "setting baseBranch should clear referenceFolderPath")
}

func TestUpdateFolderConfig_SetReferenceFolderPath_ClearsBaseBranch(t *testing.T) {
	c := testutil.UnitTest(t)

	folderPath := types.FilePath(t.TempDir())
	refDir := t.TempDir()

	fc := c.FolderConfig(folderPath)
	fc.BaseBranch = "main"
	_ = c.UpdateFolderConfig(fc)

	cmd := &updateFolderConfig{
		command: types.CommandData{
			Arguments: []any{
				string(folderPath),
				map[string]any{"referenceFolderPath": refDir},
			},
		},
		c: c,
	}

	_, err := cmd.Execute(context.Background())
	require.NoError(t, err)

	fc = c.FolderConfig(folderPath)
	assert.Equal(t, types.FilePath(refDir), fc.ReferenceFolderPath)
	assert.Empty(t, fc.BaseBranch, "setting referenceFolderPath should clear baseBranch")
}

func TestUpdateFolderConfig_ClearReferenceFolderPath(t *testing.T) {
	c := testutil.UnitTest(t)

	folderPath := types.FilePath(t.TempDir())
	refDir := types.FilePath(t.TempDir())

	fc := c.FolderConfig(folderPath)
	fc.ReferenceFolderPath = refDir
	_ = c.UpdateFolderConfig(fc)

	cmd := &updateFolderConfig{
		command: types.CommandData{
			Arguments: []any{
				string(folderPath),
				map[string]any{"referenceFolderPath": ""},
			},
		},
		c: c,
	}

	_, err := cmd.Execute(context.Background())
	require.NoError(t, err)

	fc = c.FolderConfig(folderPath)
	assert.Empty(t, fc.ReferenceFolderPath, "empty referenceFolderPath should clear it")
}

func TestUpdateFolderConfig_InvalidConfigUpdate_ReturnsError(t *testing.T) {
	c := testutil.UnitTest(t)

	cmd := &updateFolderConfig{
		command: types.CommandData{
			Arguments: []any{
				"/test/project",
				"not a map",
			},
		},
		c: c,
	}

	_, err := cmd.Execute(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config update must be a map")
}
