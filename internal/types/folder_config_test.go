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

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time check that *FolderConfig implements ImmutableFolderConfig
var _ ImmutableFolderConfig = (*FolderConfig)(nil)

func TestFolderConfig_GetFolderPath(t *testing.T) {
	t.Run("returns folder path", func(t *testing.T) {
		fc := &FolderConfig{FolderPath: "/test/path"}
		assert.Equal(t, FilePath("/test/path"), fc.GetFolderPath())
	})

	t.Run("returns empty for nil receiver", func(t *testing.T) {
		var fc *FolderConfig
		assert.Equal(t, FilePath(""), fc.GetFolderPath())
	})
}

func TestFolderConfig_GetPreferredOrg(t *testing.T) {
	t.Run("returns preferred org", func(t *testing.T) {
		fc := &FolderConfig{PreferredOrg: "my-org"}
		assert.Equal(t, "my-org", fc.GetPreferredOrg())
	})

	t.Run("returns empty for nil receiver", func(t *testing.T) {
		var fc *FolderConfig
		assert.Equal(t, "", fc.GetPreferredOrg())
	})
}

func TestFolderConfig_GetBaseBranch(t *testing.T) {
	t.Run("returns base branch", func(t *testing.T) {
		fc := &FolderConfig{BaseBranch: "main"}
		assert.Equal(t, "main", fc.GetBaseBranch())
	})

	t.Run("returns empty for nil receiver", func(t *testing.T) {
		var fc *FolderConfig
		assert.Equal(t, "", fc.GetBaseBranch())
	})
}

func TestFolderConfig_GetAdditionalParameters(t *testing.T) {
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

func TestFolderConfig_GetAdditionalEnv(t *testing.T) {
	t.Run("returns additional env", func(t *testing.T) {
		fc := &FolderConfig{AdditionalEnv: "FOO=bar"}
		assert.Equal(t, "FOO=bar", fc.GetAdditionalEnv())
	})

	t.Run("returns empty for nil receiver", func(t *testing.T) {
		var fc *FolderConfig
		assert.Equal(t, "", fc.GetAdditionalEnv())
	})
}

func TestFolderConfig_GetReferenceFolderPath(t *testing.T) {
	t.Run("returns reference folder path", func(t *testing.T) {
		fc := &FolderConfig{ReferenceFolderPath: "/ref/path"}
		assert.Equal(t, FilePath("/ref/path"), fc.GetReferenceFolderPath())
	})

	t.Run("returns empty for nil receiver", func(t *testing.T) {
		var fc *FolderConfig
		assert.Equal(t, FilePath(""), fc.GetReferenceFolderPath())
	})
}

func TestFolderConfig_GetFeatureFlag(t *testing.T) {
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

func TestFolderConfig_HasUserOverride_Interface(t *testing.T) {
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

func TestFolderConfig_GetUserOverride_Interface(t *testing.T) {
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

// FC-049: FolderConfig.SetUserOverride dual-writes to Configuration
func TestFolderConfig_SetUserOverride_DualWritesToConfiguration(t *testing.T) {
	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	fc := &FolderConfig{FolderPath: "/path/to/folder"}
	fc.SetConf(conf)

	fc.SetUserOverride("snyk_code_enabled", true)

	assert.Equal(t, true, fc.UserOverrides["snyk_code_enabled"])
	got := conf.Get(configuration.UserFolderKey("/path/to/folder", "snyk_code_enabled"))
	lf, ok := got.(*configuration.LocalConfigField)
	require.True(t, ok, "expected *LocalConfigField, got %T", got)
	assert.Equal(t, true, lf.Value)
	assert.True(t, lf.Changed)
}

// FC-050: FolderConfig.GetUserOverride reads from struct (backward compat)
func TestFolderConfig_GetUserOverride_ReadsFromStruct(t *testing.T) {
	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	fc := &FolderConfig{FolderPath: "/path/to/folder"}
	fc.SetConf(conf)

	fc.SetUserOverride("snyk_code_enabled", true)

	val, exists := fc.GetUserOverride("snyk_code_enabled")
	assert.True(t, exists)
	assert.Equal(t, true, val)
	assert.True(t, fc.HasUserOverride("snyk_code_enabled"))
}

// FC-051: FolderConfig metadata dual-writes to Configuration
func TestFolderConfig_SyncToConfiguration_MetadataDualWrites(t *testing.T) {
	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	fc := &FolderConfig{
		FolderPath:        "/path/to/folder",
		PreferredOrg:      "org123",
		AutoDeterminedOrg: "org456",
		OrgSetByUser:      true,
		BaseBranch:        "main",
	}
	fc.SetConf(conf)

	fc.SyncToConfiguration()

	assert.Equal(t, "org123", conf.Get(configuration.FolderMetadataKey("/path/to/folder", "preferred_org")))
	assert.Equal(t, "org456", conf.Get(configuration.FolderMetadataKey("/path/to/folder", "auto_determined_org")))
	assert.Equal(t, true, conf.Get(configuration.FolderMetadataKey("/path/to/folder", "org_set_by_user")))
	assert.Equal(t, "main", conf.Get(configuration.FolderMetadataKey("/path/to/folder", "base_branch")))
}

// FC-052: FolderPath normalization — PathKey produces consistent prefix keys
func TestFolderConfig_PathKey_Normalization(t *testing.T) {
	path1 := PathKey("/path/to/folder/")
	path2 := PathKey("/path/to/folder")
	key1 := configuration.UserFolderKey(string(path1), "snyk_code_enabled")
	key2 := configuration.UserFolderKey(string(path2), "snyk_code_enabled")
	assert.Equal(t, key1, key2, "PathKey-normalized paths should produce consistent prefix keys")
}

func TestFolderConfig_ResetToDefault_ClearsStructAndConfiguration(t *testing.T) {
	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	fc := &FolderConfig{FolderPath: "/path/to/folder"}
	fc.SetConf(conf)
	fc.SetUserOverride("snyk_code_enabled", true)

	fc.ResetToDefault("snyk_code_enabled")

	_, exists := fc.UserOverrides["snyk_code_enabled"]
	assert.False(t, exists)
	key := configuration.UserFolderKey("/path/to/folder", "snyk_code_enabled")
	got := conf.Get(key)
	lf, ok := got.(*configuration.LocalConfigField)
	assert.False(t, ok && lf != nil && lf.Changed, "Config should not have active override after ResetToDefault")
}

func TestFolderConfig_WhenConfNil_WorksAsBefore(t *testing.T) {
	fc := &FolderConfig{FolderPath: "/path/to/folder"}
	fc.SetConf(nil)

	fc.SetUserOverride("snyk_code_enabled", true)
	assert.Equal(t, true, fc.UserOverrides["snyk_code_enabled"])
	val, exists := fc.GetUserOverride("snyk_code_enabled")
	assert.True(t, exists)
	assert.Equal(t, true, val)

	fc.ResetToDefault("snyk_code_enabled")
	_, exists = fc.UserOverrides["snyk_code_enabled"]
	assert.False(t, exists)
}

func TestFolderConfig_SyncToConfiguration_WritesAllUserOverridesAndMetadata(t *testing.T) {
	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	fc := &FolderConfig{
		FolderPath:   "/path/to/folder",
		PreferredOrg: "org123",
		UserOverrides: map[string]any{
			"snyk_code_enabled":    true,
			"risk_score_threshold": 500,
		},
	}
	fc.SetConf(conf)

	fc.SyncToConfiguration()

	lf1 := conf.Get(configuration.UserFolderKey("/path/to/folder", "snyk_code_enabled")).(*configuration.LocalConfigField)
	assert.Equal(t, true, lf1.Value)
	assert.True(t, lf1.Changed)

	lf2 := conf.Get(configuration.UserFolderKey("/path/to/folder", "risk_score_threshold")).(*configuration.LocalConfigField)
	assert.Equal(t, 500, lf2.Value)
	assert.True(t, lf2.Changed)

	assert.Equal(t, "org123", conf.Get(configuration.FolderMetadataKey("/path/to/folder", "preferred_org")))
}

func TestFolderConfig_Clone_CopiesConfReference(t *testing.T) {
	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	fc := &FolderConfig{FolderPath: "/clone/path", UserOverrides: map[string]any{"x": 1}}
	fc.SetConf(conf)

	clone := fc.Clone()

	require.NotNil(t, clone)
	clone.SetUserOverride("snyk_code_enabled", true)
	lf := conf.Get(configuration.UserFolderKey("/clone/path", "snyk_code_enabled")).(*configuration.LocalConfigField)
	assert.Equal(t, true, lf.Value, "clone should dual-write via shared conf reference")
}
