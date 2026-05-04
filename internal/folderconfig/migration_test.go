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

package folderconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/internal/storage"
	"github.com/snyk/snyk-ls/internal/types"
)

// runMigrationFromFixture copies the input fixture to a temp storage file, sets up
// configuration + storage, refreshes INTERNAL_LS_CONFIG, runs migration, and
// returns the configuration and path to the resulting storage file.
func runMigrationFromFixture(t *testing.T, inputFixture string) (configuration.Configuration, string) {
	t.Helper()
	input, err := os.ReadFile(inputFixture)
	require.NoError(t, err)

	storageFile := filepath.Join(t.TempDir(), "ls-config-test")
	require.NoError(t, os.WriteFile(storageFile, input, 0644))

	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	conf.PersistInStorage(ConfigMainKey)
	s, err := storage.NewStorageWithCallbacks(storage.WithStorageFile(storageFile))
	require.NoError(t, err)
	conf.SetStorage(s)
	require.NoError(t, s.Refresh(conf, ConfigMainKey))

	logger := zerolog.New(zerolog.NewTestWriter(t))
	MigrateFromLegacyConfig(conf, &logger)

	return conf, storageFile
}

func Test_MigrateFromLegacyConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		inputFixture    string
		expectedFixture string
	}{
		{
			name:            "single folder with all migrated fields",
			inputFixture:    "testdata/migration_all_fields_input.json",
			expectedFixture: "testdata/migration_all_fields_expected.json",
		},
		{
			name:            "multiple folders with different settings",
			inputFixture:    "testdata/migration_multiple_folders_input.json",
			expectedFixture: "testdata/migration_multiple_folders_expected.json",
		},
		{
			name:            "partial fields only migrates non-zero values",
			inputFixture:    "testdata/migration_partial_fields_input.json",
			expectedFixture: "testdata/migration_partial_fields_expected.json",
		},
		{
			name:            "malformed JSON clears key without panic",
			inputFixture:    "testdata/migration_malformed_input.json",
			expectedFixture: "testdata/migration_malformed_expected.json",
		},
		{
			name:            "preserves orgSetByUser false",
			inputFixture:    "testdata/migration_org_set_by_user_false_input.json",
			expectedFixture: "testdata/migration_org_set_by_user_false_expected.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, storageFile := runMigrationFromFixture(t, tt.inputFixture)

			actual, err := os.ReadFile(storageFile)
			require.NoError(t, err)
			expected, err := os.ReadFile(tt.expectedFixture)
			require.NoError(t, err)
			assert.JSONEq(t, normalizeFixtureKeys(t, string(expected)), string(actual))
		})
	}
}

func Test_MigrateFromLegacyConfig_NoOp_WhenEmpty(t *testing.T) {
	t.Parallel()
	storageFile := filepath.Join(t.TempDir(), "ls-config-test")
	require.NoError(t, os.WriteFile(storageFile, []byte("{}"), 0644))

	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	conf.PersistInStorage(ConfigMainKey)
	s, err := storage.NewStorageWithCallbacks(storage.WithStorageFile(storageFile))
	require.NoError(t, err)
	conf.SetStorage(s)

	logger := zerolog.New(zerolog.NewTestWriter(t))
	MigrateFromLegacyConfig(conf, &logger)

	actual, err := os.ReadFile(storageFile)
	require.NoError(t, err)
	assert.JSONEq(t, `{}`, string(actual))
}

func Test_MigrateFromLegacyConfig_Idempotent(t *testing.T) {
	t.Parallel()
	conf, storageFile := runMigrationFromFixture(t,
		"testdata/migration_partial_fields_input.json")

	// Change a value after first migration
	types.SetFolderUserSetting(conf, "/Users/test/partial", types.SettingBaseBranch, "develop")

	// Run migration again — should be no-op since ConfigMainKey was cleared
	logger := zerolog.New(zerolog.NewTestWriter(t))
	MigrateFromLegacyConfig(conf, &logger)

	// Value should be "develop" (not reverted to "main")
	snap := types.ReadFolderConfigSnapshot(conf, "/Users/test/partial")
	assert.Equal(t, "develop", snap.BaseBranch)

	// Disk should reflect "develop" too
	actual, err := os.ReadFile(storageFile)
	require.NoError(t, err)
	assert.Contains(t, string(actual), `"develop"`)
	assert.NotContains(t, string(actual), `"value":"main"`)
}

// normalizeFixtureKeys parses expected JSON and applies PathKey to the path
// portion of config keys so fixtures (which use forward slashes) match
// platform-specific output on Windows where filepath.Clean converts to backslashes.
func normalizeFixtureKeys(t *testing.T, jsonStr string) string {
	t.Helper()
	var m map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(jsonStr), &m))

	normalized := make(map[string]json.RawMessage, len(m))
	for k, v := range m {
		normalized[normalizeFolderPathInKey(k)] = v
	}
	out, err := json.Marshal(normalized)
	require.NoError(t, err)
	return string(out)
}

// normalizeFolderPathInKey applies PathKey to the path segment inside config
// keys like "user:folder:<path>:<name>" or "folder:<path>:<name>".
func normalizeFolderPathInKey(key string) string {
	const folderPrefix = "folder:"

	idx := strings.Index(key, folderPrefix)
	if idx < 0 {
		return key
	}

	prefix := key[:idx+len(folderPrefix)]
	rest := key[idx+len(folderPrefix):]
	lastColon := strings.LastIndex(rest, ":")
	if lastColon <= 0 {
		return key
	}

	path := rest[:lastColon]
	suffix := rest[lastColon:]
	return prefix + string(types.PathKey(types.FilePath(path))) + suffix
}
