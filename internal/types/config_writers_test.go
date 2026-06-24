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

package types_test

import (
	"path/filepath"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/types"
)

// confWithFlagset builds a configuration backed by isolated per-test JSON storage.
// UnsetGlobalUser triggers PersistInStorage, so without an isolated storage path
// the Unset would write to the shared on-disk config file and leak into sibling
// tests. Pointing storage at t.TempDir() keeps each test hermetic.
func confWithFlagset(t *testing.T) configuration.Configuration {
	t.Helper()
	conf := configuration.NewWithOpts()
	conf.SetStorage(configuration.NewJsonStorage(filepath.Join(t.TempDir(), "config.json")))
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	require.NoError(t, conf.AddFlagSet(fs))
	return conf
}

func TestHasGlobalUserOverride(t *testing.T) {
	conf := confWithFlagset(t)

	assert.False(t, types.HasGlobalUserOverride(conf, types.SettingSnykCodeEnabled),
		"no override exists initially")

	types.SetGlobalUser(conf, types.SettingSnykCodeEnabled, false)
	assert.True(t, types.HasGlobalUserOverride(conf, types.SettingSnykCodeEnabled),
		"SetGlobalUser establishes a user override")
}

func TestUnsetGlobalUser_FallsBackToFlagsetDefault(t *testing.T) {
	conf := confWithFlagset(t)

	// snyk_oss_enabled defaults to true; override it to false, then reset.
	types.SetGlobalUser(conf, types.SettingSnykOssEnabled, false)
	require.True(t, types.HasGlobalUserOverride(conf, types.SettingSnykOssEnabled))
	require.False(t, types.GetGlobalBool(conf, types.SettingSnykOssEnabled))

	types.UnsetGlobalUser(conf, types.SettingSnykOssEnabled)

	assert.False(t, types.HasGlobalUserOverride(conf, types.SettingSnykOssEnabled),
		"override cleared after UnsetGlobalUser")
	assert.True(t, types.GetGlobalBool(conf, types.SettingSnykOssEnabled),
		"effective value reverts to the flagset default (true) once the override is gone")
}

func TestUnsetGlobalUser_NoOverride_IsSafe(t *testing.T) {
	conf := confWithFlagset(t)
	// Should not panic or alter the default when nothing is set.
	types.UnsetGlobalUser(conf, types.SettingSnykCodeEnabled)
	assert.False(t, types.HasGlobalUserOverride(conf, types.SettingSnykCodeEnabled))
}

func TestGlobalResettableSettings_Membership(t *testing.T) {
	set := make(map[string]bool, len(types.GlobalResettableSettings))
	for _, s := range types.GlobalResettableSettings {
		set[s] = true
	}

	// organization is global-only and must be present.
	assert.True(t, set[types.SettingOrganization], "organization must be resettable globally")
	// preferred_org is folder-only and must NOT be in the global list.
	assert.False(t, set[types.SettingPreferredOrg], "preferred_org is folder-only")
	// A representative org-scope setting that the folder reset also clears.
	assert.True(t, set[types.SettingSnykCodeEnabled])
	assert.True(t, set[types.SettingRiskScoreThreshold])
}
