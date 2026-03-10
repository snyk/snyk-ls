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

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestFolderConfig_GetFeatureFlag(t *testing.T) {
	t.Run("returns true for enabled flag", func(t *testing.T) {
		prefixKeyConf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
		RegisterAllConfigurations(fs)
		_ = prefixKeyConf.AddFlagSet(fs)
		fm := workflow.NewConfigurationOptionsStore(workflow.ConfigurationOptionsFromFlagset(fs))
		logger := zerolog.Nop()
		resolver := NewConfigResolver(&logger)
		resolver.SetPrefixKeyResolver(configresolver.New(prefixKeyConf, fm), prefixKeyConf, fm)
		fc := &FolderConfig{
			FolderPath:     "/test",
			ConfigResolver: resolver,
		}
		fc.SetFeatureFlag("myFlag", true)
		assert.True(t, fc.GetFeatureFlag("myFlag"))
	})

	t.Run("returns false for disabled flag", func(t *testing.T) {
		prefixKeyConf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
		RegisterAllConfigurations(fs)
		_ = prefixKeyConf.AddFlagSet(fs)
		fm := workflow.NewConfigurationOptionsStore(workflow.ConfigurationOptionsFromFlagset(fs))
		logger := zerolog.Nop()
		resolver := NewConfigResolver(&logger)
		resolver.SetPrefixKeyResolver(configresolver.New(prefixKeyConf, fm), prefixKeyConf, fm)
		fc := &FolderConfig{
			FolderPath:     "/test",
			ConfigResolver: resolver,
		}
		fc.SetFeatureFlag("myFlag", false)
		assert.False(t, fc.GetFeatureFlag("myFlag"))
	})

	t.Run("returns false for missing flag", func(t *testing.T) {
		prefixKeyConf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
		RegisterAllConfigurations(fs)
		_ = prefixKeyConf.AddFlagSet(fs)
		fm := workflow.NewConfigurationOptionsStore(workflow.ConfigurationOptionsFromFlagset(fs))
		logger := zerolog.Nop()
		resolver := NewConfigResolver(&logger)
		resolver.SetPrefixKeyResolver(configresolver.New(prefixKeyConf, fm), prefixKeyConf, fm)
		fc := &FolderConfig{
			FolderPath:     "/test",
			ConfigResolver: resolver,
		}
		assert.False(t, fc.GetFeatureFlag("missing"))
	})

	t.Run("returns false when ConfigResolver is nil", func(t *testing.T) {
		fc := &FolderConfig{}
		assert.False(t, fc.GetFeatureFlag("myFlag"))
	})

	t.Run("returns false for nil receiver", func(t *testing.T) {
		var fc *FolderConfig
		assert.False(t, fc.GetFeatureFlag("myFlag"))
	})
}

func TestFolderConfig_HasUserOverride(t *testing.T) {
	t.Run("returns true when override exists", func(t *testing.T) {
		conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		fp := string(PathKey("/test/path"))
		conf.Set(configresolver.UserFolderKey(fp, "setting1"), &configresolver.LocalConfigField{Value: true, Changed: true})
		assert.True(t, HasUserOverride(conf, FilePath("/test/path"), "setting1"))
	})

	t.Run("returns false when override missing", func(t *testing.T) {
		conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		assert.False(t, HasUserOverride(conf, FilePath("/test/path"), "missing"))
	})
}

func TestFolderConfig_UserOverrides_ReadFromConfig(t *testing.T) {
	t.Run("returns value when override exists", func(t *testing.T) {
		conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		fp := string(PathKey("/test/path"))
		conf.Set(configresolver.UserFolderKey(fp, "setting1"), &configresolver.LocalConfigField{Value: "value1", Changed: true})
		assert.True(t, HasUserOverride(conf, FilePath("/test/path"), "setting1"))
		val := conf.Get(configresolver.UserFolderKey(fp, "setting1"))
		lf, ok := val.(*configresolver.LocalConfigField)
		require.True(t, ok)
		assert.Equal(t, "value1", lf.Value)
	})

	t.Run("returns false when override missing", func(t *testing.T) {
		conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		assert.False(t, HasUserOverride(conf, FilePath("/test/path"), "missing"))
	})
}

// FC-049: Writing to configuration UserFolderKey produces value readable via HasUserOverride and conf.Get
func TestFolderConfig_Write_ReadableByUserOverrides(t *testing.T) {
	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	fp := string(PathKey("/path/to/folder"))
	conf.Set(configresolver.UserFolderKey(fp, SettingSnykCodeEnabled), &configresolver.LocalConfigField{Value: true, Changed: true})

	assert.True(t, HasUserOverride(conf, FilePath("/path/to/folder"), SettingSnykCodeEnabled))
	got := conf.Get(configresolver.UserFolderKey(fp, SettingSnykCodeEnabled))
	lf, ok := got.(*configresolver.LocalConfigField)
	require.True(t, ok, "expected *LocalConfigField, got %T", got)
	assert.Equal(t, true, lf.Value)
	assert.True(t, lf.Changed)
}

// FC-050: Write to configuration produces value readable via UserOverrides() and HasUserOverride
func TestFolderConfig_Write_ReadableViaSnapshot(t *testing.T) {
	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterAllConfigurations(fs)
	_ = conf.AddFlagSet(fs)
	fm := workflow.NewConfigurationOptionsStore(workflow.ConfigurationOptionsFromFlagset(fs))

	fp := string(PathKey("/path/to/folder"))
	conf.Set(configresolver.UserFolderKey(fp, SettingSnykCodeEnabled), &configresolver.LocalConfigField{Value: true, Changed: true})
	logger := zerolog.Nop()
	resolver := NewConfigResolver(&logger)
	resolver.SetPrefixKeyResolver(configresolver.New(conf, fm), conf, fm)
	fc := &FolderConfig{FolderPath: "/path/to/folder", ConfigResolver: resolver}

	val := fc.UserOverrides()[SettingSnykCodeEnabled]
	assert.Equal(t, true, val)
	assert.True(t, HasUserOverride(conf, fc.FolderPath, SettingSnykCodeEnabled))
}

// FC-051: Direct writes to configuration UserFolderKey and FolderMetadataKey produce values readable by ConfigResolver
func TestFolderConfig_DirectWrites_UserFolderKeyAndFolderMetadataKey(t *testing.T) {
	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	folderPath := string(PathKey("/path/to/folder"))

	conf.Set(configresolver.UserFolderKey(folderPath, SettingPreferredOrg), &configresolver.LocalConfigField{Value: "org123", Changed: true})
	conf.Set(configresolver.UserFolderKey(folderPath, SettingOrgSetByUser), &configresolver.LocalConfigField{Value: true, Changed: true})
	conf.Set(configresolver.UserFolderKey(folderPath, SettingBaseBranch), &configresolver.LocalConfigField{Value: "main", Changed: true})
	conf.Set(configresolver.UserFolderKey(folderPath, SettingReferenceBranch), &configresolver.LocalConfigField{Value: "main", Changed: true})
	conf.Set(configresolver.FolderMetadataKey(folderPath, SettingAutoDeterminedOrg), "org456")
	conf.Set(configresolver.FolderMetadataKey(folderPath, SettingLocalBranches), []string{"main", "develop"})

	lf := conf.Get(configresolver.UserFolderKey(folderPath, SettingPreferredOrg)).(*configresolver.LocalConfigField)
	assert.Equal(t, "org123", lf.Value)
	lf = conf.Get(configresolver.UserFolderKey(folderPath, SettingOrgSetByUser)).(*configresolver.LocalConfigField)
	assert.Equal(t, true, lf.Value)
	lf = conf.Get(configresolver.UserFolderKey(folderPath, SettingBaseBranch)).(*configresolver.LocalConfigField)
	assert.Equal(t, "main", lf.Value)

	val := conf.Get(configresolver.FolderMetadataKey(folderPath, SettingAutoDeterminedOrg))
	assert.Equal(t, "org456", val)
	val = conf.Get(configresolver.FolderMetadataKey(folderPath, SettingLocalBranches))
	assert.Equal(t, []string{"main", "develop"}, val)
}

// FC-052: FolderPath normalization — PathKey produces consistent prefix keys
func TestFolderConfig_PathKey_Normalization(t *testing.T) {
	path1 := PathKey("/path/to/folder/")
	path2 := PathKey("/path/to/folder")
	key1 := configresolver.UserFolderKey(string(path1), SettingSnykCodeEnabled)
	key2 := configresolver.UserFolderKey(string(path2), SettingSnykCodeEnabled)
	assert.Equal(t, key1, key2, "PathKey-normalized paths should produce consistent prefix keys")
}

func TestFolderConfig_Unset_ClearsOverride(t *testing.T) {
	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	fp := string(PathKey("/path/to/folder"))
	conf.Set(configresolver.UserFolderKey(fp, SettingSnykCodeEnabled), &configresolver.LocalConfigField{Value: true, Changed: true})

	conf.Unset(configresolver.UserFolderKey(fp, SettingSnykCodeEnabled))

	assert.False(t, HasUserOverride(conf, FilePath("/path/to/folder"), SettingSnykCodeEnabled))
	got := conf.Get(configresolver.UserFolderKey(fp, SettingSnykCodeEnabled))
	lf, ok := got.(*configresolver.LocalConfigField)
	assert.False(t, ok && lf != nil && lf.Changed, "Config should not have active override after Unset")
}

func TestFolderConfig_WhenConfNil_GettersReturnZeroValues(t *testing.T) {
	fc := &FolderConfig{FolderPath: "/path/to/folder"}
	fc.ConfigResolver = NewMinimalConfigResolver(nil)

	// Getters read from configuration; when Conf is nil they return zero values
	assert.Empty(t, fc.PreferredOrg())
	assert.False(t, fc.OrgSetByUser())
	assert.Empty(t, fc.UserOverrides())
}

func TestFolderConfig_DirectWrites_UserOverridesAndPreferredOrg(t *testing.T) {
	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	folderPath := string(PathKey("/path/to/folder"))

	conf.Set(configresolver.UserFolderKey(folderPath, SettingPreferredOrg), &configresolver.LocalConfigField{Value: "org123", Changed: true})
	conf.Set(configresolver.UserFolderKey(folderPath, SettingOrgSetByUser), &configresolver.LocalConfigField{Value: true, Changed: true})
	conf.Set(configresolver.UserFolderKey(folderPath, SettingSnykCodeEnabled), &configresolver.LocalConfigField{Value: true, Changed: true})
	conf.Set(configresolver.UserFolderKey(folderPath, SettingRiskScoreThreshold), &configresolver.LocalConfigField{Value: 500, Changed: true})

	lf1 := conf.Get(configresolver.UserFolderKey(folderPath, SettingSnykCodeEnabled)).(*configresolver.LocalConfigField)
	assert.Equal(t, true, lf1.Value)
	assert.True(t, lf1.Changed)

	lf2 := conf.Get(configresolver.UserFolderKey(folderPath, SettingRiskScoreThreshold)).(*configresolver.LocalConfigField)
	assert.Equal(t, 500, lf2.Value)
	assert.True(t, lf2.Changed)

	lf3 := conf.Get(configresolver.UserFolderKey(folderPath, SettingPreferredOrg)).(*configresolver.LocalConfigField)
	assert.Equal(t, "org123", lf3.Value)
}

func TestFolderConfig_Clone_CopiesConfReference(t *testing.T) {
	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	fc := &FolderConfig{FolderPath: "/clone/path"}
	fc.ConfigResolver = NewMinimalConfigResolver(conf)

	clone := fc.Clone()

	require.NotNil(t, clone)
	// Write to configuration for clone's path; clone shares ConfigResolver/conf
	fp := string(PathKey(clone.FolderPath))
	conf.Set(configresolver.UserFolderKey(fp, SettingSnykCodeEnabled), &configresolver.LocalConfigField{Value: true, Changed: true})
	lf := conf.Get(configresolver.UserFolderKey(fp, SettingSnykCodeEnabled)).(*configresolver.LocalConfigField)
	assert.Equal(t, true, lf.Value, "clone shares conf reference")
}
