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
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/data_structure"
	"github.com/snyk/snyk-ls/internal/notification"
)

func TestIsSastEnabled(t *testing.T) {
	apiClient := &snyk_api.FakeApiClient{
		CodeEnabled: false,
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

	t.Run("should return false if Snyk Code is disabled", func(t *testing.T) {
		mockedSastResponse.SastEnabled = false

		enabled := scanner.isSastEnabled(mockedSastResponse)

		assert.False(t, enabled)
	})

	t.Run("should return true if Snyk Code is enabled", func(t *testing.T) {
		config.CurrentConfig().SetSnykCodeEnabled(true)
		mockedSastResponse.SastEnabled = true
		enabled := scanner.isSastEnabled(mockedSastResponse)

		assert.True(t, enabled)
	})

	t.Run("should return false if Snyk Code is enabled and API's SAST is disabled", func(t *testing.T) {
		config.CurrentConfig().SetSnykCodeEnabled(true)
		mockedSastResponse.SastEnabled = false
		enabled := scanner.isSastEnabled(mockedSastResponse)

		assert.False(t, enabled)
	})

	t.Run("should send a ShowMessageRequest notification if Snyk Code is enabled and the API returns false",
		func(t *testing.T) {
			mockedSastResponse.SastEnabled = false

			config.CurrentConfig().SetSnykCodeEnabled(true)
			notifier := notification.NewNotifier()
			// overwrite notifiedScanner, as we want our separate notifier
			notifiedScanner := &Scanner{
				SnykApiClient: apiClient,
				errorReporter: error_reporting.NewTestErrorReporter(),
				notifier:      notifier,
			}
			actionMap := data_structure.NewOrderedMap[snyk.MessageAction, snyk.CommandData]()

			actionMap.Add(enableSnykCodeMessageActionItemTitle, snyk.CommandData{
				Title:     snyk.OpenBrowserCommand,
				CommandId: snyk.OpenBrowserCommand,
				Arguments: []any{getCodeEnablementUrl()},
			})
			actionMap.Add(closeMessageActionItemTitle, snyk.CommandData{})
			expectedShowMessageRequest := snyk.ShowMessageRequest{
				Message: codeDisabledInOrganisationMessageText,
				Type:    snyk.Warning,
				Actions: actionMap,
			}

			channel := make(chan any)

			notifier.CreateListener(func(params any) {
				channel <- params
			})
			defer notifier.DisposeListener()

			notifiedScanner.isSastEnabled(mockedSastResponse)
			assert.Equal(t, expectedShowMessageRequest, <-channel)
		})

	for _, autofixEnabled := range []bool{true, false} {
		autofixEnabledStr := strconv.FormatBool(autofixEnabled)

		t.Run("should return "+autofixEnabledStr+" if Snyk Code is enabled and the API returns "+autofixEnabledStr, func(t *testing.T) {
			apiClient.CodeEnabled = true
			apiClient.AutofixEnabled = autofixEnabled
			mockedSastResponse.SastEnabled = true
			mockedSastResponse.AutofixEnabled = autofixEnabled
			scanner.isSastEnabled(mockedSastResponse)

			assert.Equal(t, autofixEnabled, getCodeSettings().isAutofixEnabled.Get())
		})
	}
}
