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
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
)

func TestGetCodeApiUrl(t *testing.T) {
	t.Run("Snykgov instances code api url generation", func(t *testing.T) {
		t.Setenv("DEEPROXY_API_URL", "")

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
				c := config.CurrentConfig()
				random, _ := uuid.NewRandom()
				orgUUID := random.String()

				c.UpdateApiEndpoints(input)
				c.SetOrganization(orgUUID)

				expected := "https://api." + instance + ".io/hidden/orgs/" + orgUUID + "/code"

				actual, err := GetCodeApiUrl(c)
				assert.Nil(t, err)
				assert.Contains(t, actual, expected)
			}
		}
	})

	t.Run("Deeproxy instances code api url generation", func(t *testing.T) {
		t.Setenv("DEEPROXY_API_URL", "")

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
				c := config.CurrentConfig()
				c.UpdateApiEndpoints(input)

				actual, err := GetCodeApiUrl(c)
				assert.Nil(t, err)
				assert.Contains(t, actual, expected)
			}
		}
	})

	t.Run("Default deeprox url for code api", func(t *testing.T) {
		c := config.CurrentConfig()

		url, _ := GetCodeApiUrl(c)
		assert.Equal(t, c.SnykCodeApi(), url)
	})
}
