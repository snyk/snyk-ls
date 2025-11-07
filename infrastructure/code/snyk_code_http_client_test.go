/*
 * © 2022-2024 Snyk Limited
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

package code

import (
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow/sast_contract"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/storage"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestGetCodeApiUrl(t *testing.T) {
	t.Run("Snykgov instances code api url generation", func(t *testing.T) {
		t.Setenv("DEEPROXY_API_URL", "")
		c := testutil.UnitTest(t)

		var snykgovInstances = []string{
			"snykgov",
			"fedramp-alpha.snykgov",
		}

		for _, instance := range snykgovInstances {
			inputList := []string{
				"https://" + instance + ".io/api/v1",
				"https://" + instance + ".io/api",
				"https://app." + instance + ".io/api",
				"https://app." + instance + ".io/api/v1",
				"https://api." + instance + ".io/api/v1",
				"https://api." + instance + ".io/v1",
				"https://api." + instance + ".io",
				"https://api." + instance + ".io?something=here",
			}

			for _, input := range inputList {
				orgUUID, folder, err := createTempDirFolderConfig(t, c, input)
				assert.NoError(t, err)
				c.UpdateApiEndpoints(input)

				expected := "https://api." + instance + ".io/hidden/orgs/" + orgUUID + "/code"

				actual, err := GetCodeApiUrlForFolder(c, types.FilePath(folder))
				assert.Nil(t, err)
				assert.Contains(t, actual, expected)
			}
		}
	})

	t.Run("Deeproxy instances code api url generation", func(t *testing.T) {
		t.Setenv("DEEPROXY_API_URL", "")
		c := testutil.UnitTest(t)
		var deeproxyInstances = []string{
			"snyk",
			"au.snyk",
			"dev.snyk",
		}

		for _, instance := range deeproxyInstances {
			inputList := []string{
				"https://" + instance + ".io/api/v1",
				"https://" + instance + ".io/api",
				"https://app." + instance + ".io/api",
				"https://app." + instance + ".io/api/v1",
				"https://api." + instance + ".io/api/v1",
				"https://api." + instance + ".io/v1",
				"https://api." + instance + ".io",
				"https://api." + instance + ".io?something=here",
			}

			expected := "https://deeproxy." + instance + ".io"

			for _, input := range inputList {
				_, folder, err := createTempDirFolderConfig(t, c, input)
				assert.NoError(t, err)
				c.UpdateApiEndpoints(input)

				actual, err := GetCodeApiUrlForFolder(c, types.FilePath(folder))
				assert.Nil(t, err)
				assert.Contains(t, actual, expected)
			}
		}
	})

	t.Run("Default deeprox url for code api", func(t *testing.T) {
		c := testutil.UnitTest(t)
		_, folder, err := createTempDirFolderConfig(t, c, "")
		assert.NoError(t, err)
		url, _ := GetCodeApiUrlForFolder(c, types.FilePath(folder))
		assert.Equal(t, config.DefaultDeeproxyApiUrl, url)
	})
}

func createTempDirFolderConfig(t *testing.T, c *config.Config, endpoint string) (string, string, error) {
	t.Helper()
	random, _ := uuid.NewRandom()
	orgUUID := random.String()
	folder := t.TempDir()
	storageFile := filepath.Join(t.TempDir(), "testStorage")
	storage, err := storage.NewStorageWithCallbacks(storage.WithStorageFile(storageFile))
	require.NoError(t, err)
	c.SetStorage(storage)

	configuration := c.Engine().GetConfiguration()
	logger := c.Logger()
	folderConfig, err := storedconfig.GetOrCreateFolderConfig(configuration, types.FilePath(folder), logger)
	require.NoError(t, err)

	sastResponse := sast_contract.SastResponse{
		SastEnabled: true,
		LocalCodeEngine: sast_contract.LocalCodeEngine{
			AllowCloudUpload: false,
			Url:              endpoint,
			Enabled:          false,
		},
		Org:                         orgUUID,
		SupportedLanguages:          nil,
		ReportFalsePositivesEnabled: false,
		AutofixEnabled:              false,
	}
	folderConfig.SastSettings = &sastResponse
	folderConfig.OrgSetByUser = true
	folderConfig.PreferredOrg = orgUUID
	folderConfig.AutoDeterminedOrg = orgUUID
	storedconfig.UpdateFolderConfig(configuration, folderConfig, logger)
	return orgUUID, folder, err
}
