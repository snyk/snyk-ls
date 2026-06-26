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

// Package folderconfig — regression test for IDE-2108.
//
// Root cause: smoke test helpers (setupPrecedenceTest, setupScanPrecedenceTest,
// setupLdxSyncTest) mutated the process-global xdg.ConfigHome to redirect the
// ls-config file into a per-test temp dir, then restored it in t.Cleanup.
// ConfigFileFromConfig falls back to xdg.ConfigFile (which reads xdg.ConfigHome)
// when no explicit SettingConfigFile is set on the engine.  When two smoke
// tests run concurrently — or when one test's Cleanup fires while another is
// still initializing — the global is clobbered: storage for test A resolves to
// test B's (or the original system) temp dir, the expected config file is
// absent, and the scan stalls / never completes.
//
// Why xdg.ConfigHome mutation is unsafe under concurrency: two goroutines each
// writing xdg.ConfigHome to their own temp dir race on a single process-global
// variable.  The race detector flags the unsynchronised writes, and either
// goroutine may read the other's value from ConfigFileFromConfig, resolving the
// config path to the wrong temp dir.  The old pattern could not be made safe
// with a mutex because ConfigFileFromConfig itself reads the global without any
// lock.
//
// Fix: set types.SettingConfigFile on the engine configuration to a per-test
// path.  ConfigFileFromConfig checks that key first and never consults
// xdg.ConfigHome.  The global is never mutated; concurrent tests are fully
// isolated.
//
// This file contains unit-level regression tests that are runnable without a
// Snyk token or network access and verify the isolation invariant directly.
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

// TestConfigHomeIsolation_ExplicitConfigFileBypassesGlobal verifies the CORRECT
// pattern: when SettingConfigFile is set on the engine configuration, ConfigFileFromConfig
// returns that explicit path — never consulting xdg.ConfigHome.
//
// This is the GREEN test that must pass after the fix.  It is also the
// isolation invariant whose violation caused IDE-2108: a concurrent test setting
// xdg.ConfigHome to a different value must NOT affect a test that uses the
// explicit-config-file approach.
func TestConfigHomeIsolation_ExplicitConfigFileBypassesGlobal(t *testing.T) {
	t.Parallel()

	perTestConfigDir := t.TempDir()
	perTestConfigFile := filepath.Join(perTestConfigDir, "ls-config.json")

	conf := configuration.NewWithOpts()
	// The correct pattern used after the fix: set the config file on the engine config.
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
