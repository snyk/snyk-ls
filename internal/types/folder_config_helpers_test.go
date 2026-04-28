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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/util"

	"github.com/snyk/snyk-ls/internal/storage"
)

func Test_coerceToLocalConfigField_pointer(t *testing.T) {
	input := &configresolver.LocalConfigField{Value: "hello", Changed: true}
	result, ok := util.CoerceToLocalConfigField(input)
	require.True(t, ok)
	assert.Equal(t, "hello", result.Value)
	assert.True(t, result.Changed)
}

func Test_coerceToLocalConfigField_map(t *testing.T) {
	input := map[string]interface{}{"changed": true, "value": "foo"}
	result, ok := util.CoerceToLocalConfigField(input)
	require.True(t, ok)
	assert.Equal(t, "foo", result.Value)
	assert.True(t, result.Changed)
}

func Test_coerceToLocalConfigField_map_with_slice(t *testing.T) {
	input := map[string]interface{}{"changed": true, "value": []interface{}{"-d"}}
	result, ok := util.CoerceToLocalConfigField(input)
	require.True(t, ok)
	assert.Equal(t, []interface{}{"-d"}, result.Value)
	assert.True(t, result.Changed)
}

func Test_coerceToLocalConfigField_map_not_changed(t *testing.T) {
	input := map[string]interface{}{"changed": false, "value": "bar"}
	_, ok := util.CoerceToLocalConfigField(input)
	assert.False(t, ok)
}

func Test_coerceToLocalConfigField_nil(t *testing.T) {
	_, ok := util.CoerceToLocalConfigField(nil)
	assert.False(t, ok)
}

func Test_coerceToLocalConfigField_wrong_type(t *testing.T) {
	_, ok := util.CoerceToLocalConfigField("just a string")
	assert.False(t, ok)
}

// setupConfigWithStorage creates a GAF configuration backed by a JSON file for round-trip tests.
func setupConfigWithStorage(t *testing.T) (configuration.Configuration, string) {
	t.Helper()
	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	storageFile := filepath.Join(t.TempDir(), "test-config.json")
	require.NoError(t, os.WriteFile(storageFile, []byte("{}"), 0644))
	s, err := storage.NewStorageWithCallbacks(storage.WithStorageFile(storageFile))
	require.NoError(t, err)
	conf.SetStorage(s)
	return conf, storageFile
}

// newConfigFromFile creates a fresh configuration that reads persisted keys from a JSON storage file,
// simulating a language-server restart.
func newConfigFromFile(t *testing.T, storageFile string) configuration.Configuration {
	t.Helper()
	conf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	s, err := storage.NewStorageWithCallbacks(storage.WithStorageFile(storageFile))
	require.NoError(t, err)
	conf.SetStorage(s)

	// Read persisted keys from the storage file and load them into the new config.
	data, err := os.ReadFile(storageFile)
	require.NoError(t, err)
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &doc))
	for key, val := range doc {
		conf.PersistInStorage(key)
		conf.Set(key, val)
	}
	return conf
}

func Test_roundTrip_string(t *testing.T) {
	conf, storageFile := setupConfigWithStorage(t)
	folderPath := FilePath("/test/folder")

	SetFolderUserSetting(conf, folderPath, SettingBaseBranch, "main")

	// Simulate restart
	conf2 := newConfigFromFile(t, storageFile)

	snap := ReadFolderConfigSnapshot(conf2, folderPath)
	assert.Equal(t, "main", snap.BaseBranch)
	assert.True(t, HasUserOverride(conf2, folderPath, SettingBaseBranch))
}

func Test_roundTrip_bool(t *testing.T) {
	conf, storageFile := setupConfigWithStorage(t)
	folderPath := FilePath("/test/folder")

	SetFolderUserSetting(conf, folderPath, SettingOrgSetByUser, true)

	conf2 := newConfigFromFile(t, storageFile)

	snap := ReadFolderConfigSnapshot(conf2, folderPath)
	assert.True(t, snap.OrgSetByUser)
	assert.True(t, HasUserOverride(conf2, folderPath, SettingOrgSetByUser))
}

func Test_roundTrip_stringSlice(t *testing.T) {
	conf, storageFile := setupConfigWithStorage(t)
	folderPath := FilePath("/test/folder")

	SetFolderUserSetting(conf, folderPath, SettingAdditionalParameters, []string{"-d", "--verbose"})

	conf2 := newConfigFromFile(t, storageFile)

	// After JSON round-trip, []string becomes []interface{}, so we read via getUserFolderValue
	fp := string(PathKey(folderPath))
	val, ok := getUserFolderValue(conf2, fp, SettingAdditionalParameters)
	require.True(t, ok)

	// The value is []interface{} after JSON deserialization, not []string
	slice, ok := val.([]interface{})
	require.True(t, ok)
	assert.Equal(t, []interface{}{"-d", "--verbose"}, slice)
}
