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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_getCodeEnablementUrl_CustomEndpoint(t *testing.T) {
	testutil.UnitTest(t)
	config.CurrentConfig().SetIntegrationName("VS_CODE")

	t.Run("Custom endpoint configuration", func(t *testing.T) {
		config.CurrentConfig().UpdateApiEndpoints("https://custom.endpoint.com/api")
		assert.Equal(t, "https://app.custom.endpoint.com/manage/snyk-code?from=VS_CODE", getCodeEnablementUrl())
	})
	t.Run("Single tenant endpoint configuration", func(t *testing.T) {
		config.CurrentConfig().UpdateApiEndpoints("https://app.custom.snyk.io/api")
		assert.Equal(t, "https://app.custom.snyk.io/manage/snyk-code?from=VS_CODE", getCodeEnablementUrl())
	})
	t.Run("Arbitrary path in url", func(t *testing.T) {
		config.CurrentConfig().UpdateApiEndpoints("https://dev.snyk.io/api/v1")
		assert.Equal(t, "https://app.dev.snyk.io/manage/snyk-code?from=VS_CODE", getCodeEnablementUrl())
	})
}
