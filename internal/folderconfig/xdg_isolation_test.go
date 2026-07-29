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

// These tests verify that ConfigFileFromConfig returns the explicit
// SettingConfigFile (or its legacy/user-global variants) whenever one is set,
// without ever consulting the process-global xdg.ConfigHome. That invariant is
// what makes per-test config files a safe isolation mechanism under
// t.Parallel() — mutating xdg.ConfigHome directly is not, since concurrent
// writes to that global race and callers can observe each other's value.

package folderconfig

import (
	"path/filepath"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/types"
)

// TestConfigHomeIsolation_ExplicitConfigFileBypassesGlobal verifies that when
// SettingConfigFile is set on the engine configuration, ConfigFileFromConfig
// returns that explicit path — never consulting xdg.ConfigHome. A concurrent
// test setting xdg.ConfigHome to a different value must not affect a test
// that uses the explicit-config-file approach.
func TestConfigHomeIsolation_ExplicitConfigFileBypassesGlobal(t *testing.T) {
	t.Parallel()

	perTestConfigDir := t.TempDir()
	perTestConfigFile := filepath.Join(perTestConfigDir, "ls-config.json")

	conf := configuration.NewWithOpts()
	// ConfigFileFromConfig short-circuits on this key before ever reading xdg.ConfigHome,
	// so no global mutation is needed to prove precedence — and none is safe under t.Parallel().
	conf.Set(types.SettingConfigFile, perTestConfigFile)

	got, err := ConfigFileFromConfig(conf)
	require.NoError(t, err)
	assert.Equal(t, perTestConfigFile, got,
		"ConfigFileFromConfig must return the explicit SettingConfigFile path "+
			"and must NOT consult xdg.ConfigHome when the setting is present")
}

// TestConfigHomeIsolation_LegacyKeyAlsoBypassesGlobal covers the legacy
// SettingConfigFileLegacy key used by some test helpers and the extension path.
func TestConfigHomeIsolation_LegacyKeyAlsoBypassesGlobal(t *testing.T) {
	t.Parallel()

	perTestConfigFile := filepath.Join(t.TempDir(), "legacy-ls-config.json")

	conf := configuration.NewWithOpts()
	// ConfigFileFromConfig short-circuits on SettingConfigFileLegacy before reading xdg.ConfigHome.
	conf.Set(types.SettingConfigFileLegacy, perTestConfigFile)

	got, err := ConfigFileFromConfig(conf)
	require.NoError(t, err)
	assert.Equal(t, perTestConfigFile, got,
		"ConfigFileFromConfig must return the explicit SettingConfigFileLegacy path")
}

// TestConfigHomeIsolation_UserGlobalKeyAlsoBypassesGlobal covers the
// configresolver.UserGlobalKey-wrapped form, which is what the engine uses
// internally for user-scoped settings.
func TestConfigHomeIsolation_UserGlobalKeyAlsoBypassesGlobal(t *testing.T) {
	t.Parallel()

	perTestConfigFile := filepath.Join(t.TempDir(), "user-global-ls-config.json")

	conf := configuration.NewWithOpts()
	// ConfigFileFromConfig short-circuits on UserGlobalKey(SettingConfigFile) before reading xdg.ConfigHome.
	conf.Set(configresolver.UserGlobalKey(types.SettingConfigFile), perTestConfigFile)

	got, err := ConfigFileFromConfig(conf)
	require.NoError(t, err)
	assert.Equal(t, perTestConfigFile, got,
		"ConfigFileFromConfig must return the UserGlobal-wrapped SettingConfigFile path")
}
