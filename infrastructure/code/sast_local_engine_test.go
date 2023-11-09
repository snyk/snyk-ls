/*
 * © 2023 Snyk Limited
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
	"slices"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/notification"
)

func TestIsLocalEngine(t *testing.T) {
	apiClient := &snyk_api.FakeApiClient{
		CodeEnabled: true,
		ApiError:    nil,
	}

	mockedSastResponse := snyk_api.SastResponse{
		SastEnabled: true,
		LocalCodeEngine: snyk_api.LocalCodeEngine{
			AllowCloudUpload: false,
			Url:              "http://local.engine",
			Enabled:          true,
		},
	}

	scanner := &Scanner{
		SnykApiClient: apiClient,
		errorReporter: error_reporting.NewTestErrorReporter(),
		notifier:      notification.NewNotifier(),
	}

	t.Run("should return true if SAST and local engine is enabled is disabled", func(t *testing.T) {
		enabled := scanner.isLocalEngineEnabled(mockedSastResponse)
		assert.True(t, enabled)
	})

	t.Run("should return false if SAST is enabled local engine is disabled", func(t *testing.T) {
		mockedSastResponse.LocalCodeEngine.Enabled = false
		enabled := scanner.isLocalEngineEnabled(mockedSastResponse)
		assert.False(t, enabled)
	})

	t.Run("should return false if SAST is enabled local engine is disabled", func(t *testing.T) {
		mockedSastResponse.LocalCodeEngine.Enabled = true
		mockedSastResponse.SastEnabled = false
		enabled := scanner.isLocalEngineEnabled(mockedSastResponse)
		assert.False(t, enabled)
	})

	t.Run("should update Snyk Code API if local-engine is enabled", func(t *testing.T) {
		mockedSastResponse.SastEnabled = true
		mockedSastResponse.LocalCodeEngine.Enabled = true
		scanner.updateCodeApiLocalEngine(mockedSastResponse)
		assert.Equal(t, mockedSastResponse.LocalCodeEngine.Url, config.CurrentConfig().SnykCodeApi())
		additionalAuthUrls := config.CurrentConfig().Engine().GetConfiguration().GetStringSlice(configuration.
			AUTHENTICATION_ADDITIONAL_URLS)
		assert.True(t, slices.Contains(additionalAuthUrls, mockedSastResponse.LocalCodeEngine.Url))
	})
}
