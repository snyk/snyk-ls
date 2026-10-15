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

package types

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/code-client-go/pkg/code/sast_contract"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/product"
)

const copyTestOrg = "org-uuid"

func newCopyTestConfig(t *testing.T) (configuration.Configuration, *ConfigResolver, string) {
	t.Helper()
	conf, storageFile := setupConfigWithStorage(t)
	fs := pflag.NewFlagSet("copy-test", pflag.ContinueOnError)
	RegisterAllConfigurations(fs)
	require.NoError(t, conf.AddFlagSet(fs))
	fm := workflow.ConfigurationOptionsFromFlagset(fs)
	logger := zerolog.Nop()
	resolver := NewConfigResolver(&logger)
	resolver.SetPrefixKeyResolver(configresolver.New(conf, fm), conf, fm)
	return conf, resolver, storageFile
}

// seedEveryFamily writes values in all three per-folder key families, including names no code refers to.
func seedEveryFamily(conf configuration.Configuration, folder FilePath) {
	fp := string(PathKey(folder))
	SetFolderUserSetting(conf, folder, SettingBaseBranch, "develop")
	SetFolderUserSetting(conf, folder, SettingAdditionalParameters, []string{"--all-projects"})
	SetFolderUserSetting(conf, folder, "made_up_user_setting", "user-value")
	SetPreferredOrgAndOrgSetByUser(conf, folder, copyTestOrg, true)
	SetAutoDeterminedOrg(conf, folder, "auto-org")
	conf.Set(configresolver.FolderMetadataKey(fp, FeatureFlagPrefix+"flagNobodyKnows"), true)
	conf.Set(configresolver.FolderMetadataKey(fp, FeatureFlagPrefix+"enableUvCLI"), true)
	conf.Set(configresolver.FolderMetadataKey(fp, "made_up_metadata"), "meta-value")
	WriteFolderConfigToConfiguration(conf, copyTestOrg, folder, map[string]*LDXSyncField{
		SettingSeverityFilterCritical: {Value: false, IsLocked: true},
		SettingSeverityFilterHigh:     {Value: false},
		"made_up_remote_setting":      {Value: "remote-value"},
	})
}

// valuesUnder reads the value of each named key at folder. Keys are written as format strings with %s for the path.
func valuesUnder(conf configuration.Configuration, folder FilePath, keys []string) map[string]any {
	fp := string(PathKey(folder))
	out := map[string]any{}
	for _, k := range keys {
		out[k] = conf.Get(fmt.Sprintf(k, fp))
	}
	return out
}

// keysWithValueUnder lists every key holding a value whose folder part is exactly folder.
func keysWithValueUnder(conf configuration.Configuration, folder FilePath) []string {
	fp := ":" + strings.ToLower(string(PathKey(folder))) + ":"
	var out []string
	for _, key := range conf.AllKeys() {
		if strings.Contains(key, fp) && conf.Get(key) != nil {
			out = append(out, key)
		}
	}
	return out
}

var everyFamilyKeys = []string{
	"user:folder:%s:base_branch",
	"user:folder:%s:additional_parameters",
	"user:folder:%s:made_up_user_setting",
	"user:folder:%s:preferred_org",
	"user:folder:%s:org_set_by_user",
	"folder:%s:auto_determined_org",
	"folder:%s:ff_flagnobodyknows",
	"folder:%s:ff_enableuvcli",
	"folder:%s:made_up_metadata",
	"remote:" + copyTestOrg + ":folder:%s:severity_filter_critical",
	"remote:" + copyTestOrg + ":folder:%s:severity_filter_high",
	"remote:" + copyTestOrg + ":folder:%s:made_up_remote_setting",
}

func TestCopyFolderConfigValues_CopiesEveryKeyInEveryFamily(t *testing.T) {
	conf, _, _ := newCopyTestConfig(t)
	src := FilePath(t.TempDir())
	dst := FilePath(t.TempDir())
	seedEveryFamily(conf, src)

	want := valuesUnder(conf, src, everyFamilyKeys)
	require.NotContains(t, want, nil)

	CopyFolderConfigValues(conf, src, dst)

	assert.Equal(t, want, valuesUnder(conf, dst, everyFamilyKeys))
	assert.Len(t, keysWithValueUnder(conf, dst), len(everyFamilyKeys), "nothing beyond the seeded settings is written")
}

func TestCopyFolderConfigValues_EverySettingCopiedBefore(t *testing.T) {
	conf, _, _ := newCopyTestConfig(t)
	src := FilePath(t.TempDir())
	dst := FilePath(t.TempDir())
	SetFolderUserSetting(conf, src, SettingBaseBranch, "develop")
	SetFolderUserSetting(conf, src, SettingReferenceBranch, "develop")
	SetFolderUserSetting(conf, src, SettingAdditionalParameters, []string{"--all-projects"})
	SetFolderUserSetting(conf, src, SettingAdditionalEnvironment, "FOO=bar")
	SetFolderUserSetting(conf, src, SettingReferenceFolder, "/ref/path")
	SetFolderUserSetting(conf, src, SettingScanCommandConfig, map[product.Product]ScanCommandConfig{
		product.ProductCode: {PreScanCommand: "echo test"},
	})
	SetPreferredOrgAndOrgSetByUser(conf, src, "my-org", true)
	SetAutoDeterminedOrg(conf, src, "auto-org")
	SetFolderMetadataSetting(conf, src, SettingLocalBranches, []string{"main", "develop"})
	SetSastSettings(conf, src, &sast_contract.SastResponse{SastEnabled: true})
	keys := []string{
		"user:folder:%s:base_branch", "user:folder:%s:reference_branch", "user:folder:%s:additional_parameters",
		"user:folder:%s:additional_environment", "user:folder:%s:reference_folder", "user:folder:%s:scan_command_config",
		"user:folder:%s:preferred_org", "user:folder:%s:org_set_by_user",
		"folder:%s:auto_determined_org", "folder:%s:local_branches", "folder:%s:sast_settings",
	}
	want := valuesUnder(conf, src, keys)
	require.NotContains(t, want, nil)

	CopyFolderConfigValues(conf, src, dst)

	assert.Equal(t, want, valuesUnder(conf, dst, keys))
}

func TestCopyFolderConfigValues_FeatureFlagsReadSameThroughDestinationFolderConfig(t *testing.T) {
	conf, resolver, _ := newCopyTestConfig(t)
	src := &FolderConfig{FolderPath: FilePath(t.TempDir()), ConfigResolver: resolver}
	dst := &FolderConfig{FolderPath: FilePath(t.TempDir()), ConfigResolver: resolver}
	src.SetFeatureFlag("enableUvCLI", true)
	src.SetFeatureFlag("flagNobodyKnows", true)
	src.SetFeatureFlag("explicitlyOff", false)

	CopyFolderConfigValues(conf, src.FolderPath, dst.FolderPath)

	assert.True(t, dst.GetFeatureFlag("enableUvCLI"))
	assert.True(t, dst.GetFeatureFlag("flagNobodyKnows"))
	assert.False(t, dst.GetFeatureFlag("explicitlyOff"))
}

func TestCopyFolderConfigValues_RemoteOrgFolderSettingsResolveSame(t *testing.T) {
	conf, resolver, _ := newCopyTestConfig(t)
	src := &FolderConfig{FolderPath: FilePath(t.TempDir()), ConfigResolver: resolver}
	dst := &FolderConfig{FolderPath: FilePath(t.TempDir()), ConfigResolver: resolver}
	SetPreferredOrgAndOrgSetByUser(conf, src.FolderPath, copyTestOrg, true)
	WriteFolderConfigToConfiguration(conf, copyTestOrg, src.FolderPath, map[string]*LDXSyncField{
		SettingSeverityFilterCritical: {Value: false, IsLocked: true},
		SettingSeverityFilterHigh:     {Value: false},
	})
	// A user override loses to the locked remote value, but wins over the unlocked one.
	SetFolderUserSetting(conf, src.FolderPath, SettingSeverityFilterCritical, true)
	SetFolderUserSetting(conf, dst.FolderPath, SettingSeverityFilterCritical, true)

	CopyFolderConfigValues(conf, src.FolderPath, dst.FolderPath)

	for _, name := range []string{SettingSeverityFilterCritical, SettingSeverityFilterHigh} {
		srcVal, srcSource := resolver.GetValue(name, src)
		dstVal, dstSource := resolver.GetValue(name, dst)
		assert.Equal(t, srcVal, dstVal, name)
		assert.Equal(t, srcSource, dstSource, name)
	}
	_, source := resolver.GetValue(SettingSeverityFilterCritical, dst)
	assert.Equal(t, configresolver.ConfigSourceRemoteLocked, source)
	_, source = resolver.GetValue(SettingSeverityFilterHigh, dst)
	assert.Equal(t, configresolver.ConfigSourceRemote, source)
}

func TestCopyFolderConfigValues_SkipsSiblingFolderWithSharedPrefix(t *testing.T) {
	conf, _, _ := newCopyTestConfig(t)
	parent := t.TempDir()
	src := FilePath(parent + "/api")
	sibling := FilePath(parent + "/api-v2")
	dst := FilePath(t.TempDir())
	SetFolderUserSetting(conf, src, SettingBaseBranch, "main")
	SetFolderUserSetting(conf, sibling, "sibling_only", "x")
	conf.Set(configresolver.FolderMetadataKey(string(sibling), FeatureFlagPrefix+"siblingFlag"), true)

	CopyFolderConfigValues(conf, src, dst)

	assert.Equal(t, []string{"user:folder:" + strings.ToLower(string(PathKey(dst))) + ":base_branch"}, keysWithValueUnder(conf, dst))
}

func TestCopyFolderConfigValues_MixedCasePaths(t *testing.T) {
	conf, resolver, _ := newCopyTestConfig(t)
	src := &FolderConfig{FolderPath: FilePath(t.TempDir() + "/MyRepo"), ConfigResolver: resolver}
	dst := &FolderConfig{FolderPath: FilePath(t.TempDir() + "/Base_Main"), ConfigResolver: resolver}
	src.SetFeatureFlag("enableUvCLI", true)
	SetFolderUserSetting(conf, src.FolderPath, SettingBaseBranch, "Main")

	CopyFolderConfigValues(conf, src.FolderPath, dst.FolderPath)

	assert.True(t, dst.GetFeatureFlag("enableUvCLI"))
	assert.Equal(t, "Main", ReadFolderConfigSnapshot(conf, dst.FolderPath).BaseBranch)
}

func TestCopyFolderConfigValues_NoOp(t *testing.T) {
	tests := []struct {
		name     string
		src, dst func(base FilePath) FilePath
	}{
		{name: "source equals destination", src: func(b FilePath) FilePath { return b }, dst: func(b FilePath) FilePath { return b }},
		{name: "destination differs only by trailing separator", src: func(b FilePath) FilePath { return b }, dst: func(b FilePath) FilePath { return b + "/" }},
		{name: "empty source", src: func(FilePath) FilePath { return "" }, dst: func(b FilePath) FilePath { return b + "-dst" }},
		{name: "empty destination", src: func(b FilePath) FilePath { return b }, dst: func(FilePath) FilePath { return "" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conf, _, _ := newCopyTestConfig(t)
			base := FilePath(t.TempDir())
			seedEveryFamily(conf, base)
			before := conf.AllKeys()

			CopyFolderConfigValues(conf, tc.src(base), tc.dst(base))

			assert.ElementsMatch(t, before, conf.AllKeys())
		})
	}
}

func TestCopyFolderConfigValues_CopiesPersistedValuesReloadedFromStorage(t *testing.T) {
	conf, storageFile := setupConfigWithStorage(t)
	src := FilePath(t.TempDir())
	dst := FilePath(t.TempDir())
	SetFolderUserSetting(conf, src, SettingBaseBranch, "develop")
	SetFolderUserSetting(conf, src, SettingAdditionalParameters, []string{"-d"})
	SetAutoDeterminedOrg(conf, src, "auto-org")

	reloaded := newConfigFromFile(t, storageFile)
	CopyFolderConfigValues(reloaded, src, dst)

	snap := ReadFolderConfigSnapshot(reloaded, dst)
	assert.Equal(t, "develop", snap.BaseBranch)
	assert.Equal(t, []string{"-d"}, snap.AdditionalParameters)
	assert.Equal(t, "auto-org", snap.AutoDeterminedOrg)
}

func TestCopyAndClearFolderConfigValues_WriteNothingToStorage(t *testing.T) {
	conf, _, storageFile := newCopyTestConfig(t)
	src := FilePath(t.TempDir())
	dst := FilePath(t.TempDir())
	seedEveryFamily(conf, src)
	before, err := os.ReadFile(storageFile)
	require.NoError(t, err)

	CopyFolderConfigValues(conf, src, dst)
	ClearFolderConfigValues(conf, dst)

	after, err := os.ReadFile(storageFile)
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after))
	assert.NotContains(t, string(after), string(PathKey(dst)))
}

func TestClearFolderConfigValues_RemovesEveryValueUnderPathOnly(t *testing.T) {
	conf, _, _ := newCopyTestConfig(t)
	keep := FilePath(t.TempDir())
	dst := FilePath(t.TempDir())
	seedEveryFamily(conf, keep)
	CopyFolderConfigValues(conf, keep, dst)
	wantKept := valuesUnder(conf, keep, everyFamilyKeys)

	ClearFolderConfigValues(conf, dst)

	for _, key := range everyFamilyKeys {
		k := fmt.Sprintf(key, PathKey(dst))
		assert.Nil(t, conf.Get(k), k)
		assert.False(t, conf.IsSet(k), k)
	}
	assert.Empty(t, keysWithValueUnder(conf, dst))
	assert.Equal(t, wantKept, valuesUnder(conf, keep, everyFamilyKeys))
}

func TestClearFolderConfigValues_NoOp(t *testing.T) {
	conf, _, _ := newCopyTestConfig(t)
	folder := FilePath(t.TempDir())
	seedEveryFamily(conf, folder)
	want := valuesUnder(conf, folder, everyFamilyKeys)

	ClearFolderConfigValues(conf, "")
	ClearFolderConfigValues(nil, folder)

	assert.Equal(t, want, valuesUnder(conf, folder, everyFamilyKeys))
}
