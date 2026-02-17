/*
 * © 2022-2026 Snyk Limited
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

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Compile-time check that *FolderConfig implements ImmutableFolderConfig
var _ ImmutableFolderConfig = (*FolderConfig)(nil)

func TestStoredFolderConfig_GetFolderPath(t *testing.T) {
	t.Run("returns folder path", func(t *testing.T) {
		fc := &FolderConfig{FolderPath: "/test/path"}
		assert.Equal(t, FilePath("/test/path"), fc.GetFolderPath())
	})

	t.Run("returns empty for nil receiver", func(t *testing.T) {
		var fc *FolderConfig
		assert.Equal(t, FilePath(""), fc.GetFolderPath())
	})
}

func TestStoredFolderConfig_GetPreferredOrg(t *testing.T) {
	t.Run("returns preferred org", func(t *testing.T) {
		fc := &FolderConfig{PreferredOrg: "my-org"}
		assert.Equal(t, "my-org", fc.GetPreferredOrg())
	})

	t.Run("returns empty for nil receiver", func(t *testing.T) {
		var fc *FolderConfig
		assert.Equal(t, "", fc.GetPreferredOrg())
	})
}

func TestStoredFolderConfig_GetBaseBranch(t *testing.T) {
	t.Run("returns base branch", func(t *testing.T) {
		fc := &FolderConfig{BaseBranch: "main"}
		assert.Equal(t, "main", fc.GetBaseBranch())
	})

	t.Run("returns empty for nil receiver", func(t *testing.T) {
		var fc *FolderConfig
		assert.Equal(t, "", fc.GetBaseBranch())
	})
}

func TestStoredFolderConfig_GetAdditionalParameters(t *testing.T) {
	t.Run("returns additional parameters", func(t *testing.T) {
		fc := &FolderConfig{AdditionalParameters: []string{"--debug", "--verbose"}}
		assert.Equal(t, []string{"--debug", "--verbose"}, fc.GetAdditionalParameters())
	})

	t.Run("returns nil for nil receiver", func(t *testing.T) {
		var fc *FolderConfig
		assert.Nil(t, fc.GetAdditionalParameters())
	})

	t.Run("returns nil for empty slice", func(t *testing.T) {
		fc := &FolderConfig{}
		assert.Nil(t, fc.GetAdditionalParameters())
	})
}

func TestStoredFolderConfig_GetAdditionalEnv(t *testing.T) {
	t.Run("returns additional env", func(t *testing.T) {
		fc := &FolderConfig{AdditionalEnv: "FOO=bar"}
		assert.Equal(t, "FOO=bar", fc.GetAdditionalEnv())
	})

	t.Run("returns empty for nil receiver", func(t *testing.T) {
		var fc *FolderConfig
		assert.Equal(t, "", fc.GetAdditionalEnv())
	})
}

func TestStoredFolderConfig_GetReferenceFolderPath(t *testing.T) {
	t.Run("returns reference folder path", func(t *testing.T) {
		fc := &FolderConfig{ReferenceFolderPath: "/ref/path"}
		assert.Equal(t, FilePath("/ref/path"), fc.GetReferenceFolderPath())
	})

	t.Run("returns empty for nil receiver", func(t *testing.T) {
		var fc *FolderConfig
		assert.Equal(t, FilePath(""), fc.GetReferenceFolderPath())
	})
}

func TestStoredFolderConfig_GetFeatureFlag(t *testing.T) {
	t.Run("returns true for enabled flag", func(t *testing.T) {
		fc := &FolderConfig{
			FeatureFlags: map[string]bool{"myFlag": true},
		}
		assert.True(t, fc.GetFeatureFlag("myFlag"))
	})

	t.Run("returns false for disabled flag", func(t *testing.T) {
		fc := &FolderConfig{
			FeatureFlags: map[string]bool{"myFlag": false},
		}
		assert.False(t, fc.GetFeatureFlag("myFlag"))
	})

	t.Run("returns false for missing flag", func(t *testing.T) {
		fc := &FolderConfig{
			FeatureFlags: map[string]bool{},
		}
		assert.False(t, fc.GetFeatureFlag("missing"))
	})

	t.Run("returns false for nil FeatureFlags", func(t *testing.T) {
		fc := &FolderConfig{}
		assert.False(t, fc.GetFeatureFlag("myFlag"))
	})

	t.Run("returns false for nil receiver", func(t *testing.T) {
		var fc *FolderConfig
		assert.False(t, fc.GetFeatureFlag("myFlag"))
	})
}

func TestStoredFolderConfig_HasUserOverride_Interface(t *testing.T) {
	t.Run("returns true when override exists", func(t *testing.T) {
		fc := &FolderConfig{
			UserOverrides: map[string]any{"setting1": true},
		}
		var reader ImmutableFolderConfig = fc
		assert.True(t, reader.HasUserOverride("setting1"))
	})

	t.Run("returns false when override missing", func(t *testing.T) {
		fc := &FolderConfig{
			UserOverrides: map[string]any{},
		}
		var reader ImmutableFolderConfig = fc
		assert.False(t, reader.HasUserOverride("missing"))
	})
}

func TestStoredFolderConfig_GetUserOverride_Interface(t *testing.T) {
	t.Run("returns value when override exists", func(t *testing.T) {
		fc := &FolderConfig{
			UserOverrides: map[string]any{"setting1": "value1"},
		}
		var reader ImmutableFolderConfig = fc
		val, exists := reader.GetUserOverride("setting1")
		assert.True(t, exists)
		assert.Equal(t, "value1", val)
	})

	t.Run("returns nil when override missing", func(t *testing.T) {
		fc := &FolderConfig{}
		var reader ImmutableFolderConfig = fc
		val, exists := reader.GetUserOverride("missing")
		assert.False(t, exists)
		assert.Nil(t, val)
	})
}
