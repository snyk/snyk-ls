/*
 * © 2023 Snyk Limited All rights reserved.
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
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_getCodeEnablementUrl_CustomEndpoint(t *testing.T) {
	c := testutil.UnitTest(t)
	t.Cleanup(resetCodeSettings)
	c.SetIntegrationName("VS_CODE")
	path := "/manage/snyk-code?from=VS_CODE"

	t.Run("api subdomain", func(t *testing.T) {
		c.UpdateApiEndpoints("https://api.snyk.io")
		assert.Equal(t, "https://app.snyk.io"+path, getCodeEnablementUrl())
	})

	t.Run("Custom endpoint configuration", func(t *testing.T) {
		c.UpdateApiEndpoints("https://custom.endpoint.com/api")
		assert.Equal(t, "https://app.custom.endpoint.com"+path, getCodeEnablementUrl())
	})
	t.Run("Single tenant endpoint configuration", func(t *testing.T) {
		c.UpdateApiEndpoints("https://app.custom.snyk.io/api")
		assert.Equal(t, "https://app.custom.snyk.io/manage/snyk-code?from=VS_CODE", getCodeEnablementUrl())
	})
	t.Run("Arbitrary path in url", func(t *testing.T) {
		c.UpdateApiEndpoints("https://dev.snyk.io/api/v1")
		assert.Equal(t, "https://app.dev.snyk.io/manage/snyk-code?from=VS_CODE", getCodeEnablementUrl())
	})
}

func Test_getCodeSettingsSingleton(t *testing.T) {
	testutil.UnitTest(t)
	t.Cleanup(resetCodeSettings)

	t.Run("Concurrent access to the settings", func(t *testing.T) {
		wg := sync.WaitGroup{}

		// Request settings, increasing the possibility of a clash
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 10; j++ {
					getCodeSettings().isAutofixEnabled.Set(true)
				}
			}()
		}
		wg.Wait()

		assert.Equal(t, getCodeSettings().isAutofixEnabled.Get(), true)
	})
}
