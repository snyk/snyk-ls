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
	"testing"
	"time"

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/command"
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

	scanner := &Scanner{
		SnykApiClient: apiClient,
		errorReporter: error_reporting.NewTestErrorReporter(),
		notifier:      notification.NewNotifier(),
	}

	t.Run("should return false if Snyk Code is disabled", func(t *testing.T) {
		apiClient.ApiError = nil
		apiClient.CodeEnabled = false
		apiClient.LocalCodeEngineEnabled = false
		config.CurrentConfig().SetSnykCodeEnabled(false)

		enabled := scanner.isSastEnabled()

		assert.False(t, enabled)
	})

	t.Run("should call the API to check enablement if Snyk Code is enabled", func(t *testing.T) {
		apiClient.ApiError = nil
		config.CurrentConfig().SetSnykCodeEnabled(true)

		scanner.isSastEnabled()

		assert.Equal(t, 1, len(apiClient.Calls))
	})

	t.Run("should return true if Snyk Code is enabled and the API returns true", func(t *testing.T) {
		config.CurrentConfig().SetSnykCodeEnabled(true)
		apiClient.ApiError = nil
		apiClient.CodeEnabled = true
		apiClient.LocalCodeEngineEnabled = false

		enabled := scanner.isSastEnabled()

		assert.True(t, enabled)
	})

	t.Run("should return false if Snyk Code is enabled and the API returns false", func(t *testing.T) {
		config.CurrentConfig().SetSnykCodeEnabled(true)
		apiClient.ApiError = nil
		apiClient.CodeEnabled = false
		apiClient.LocalCodeEngineEnabled = false

		enabled := scanner.isSastEnabled()

		assert.False(t, enabled)
	})

	t.Run("should return false if Snyk Code is enabled and the API returns an error", func(t *testing.T) {
		config.CurrentConfig().SetSnykCodeEnabled(true)
		apiClient.ApiError = &snyk_api.SnykApiError{}
		apiClient.CodeEnabled = false
		apiClient.LocalCodeEngineEnabled = false

		enabled := scanner.isSastEnabled()

		assert.False(t, enabled)
	})

	t.Run("should return false if Snyk Code is enabled and LocalCodeEngine is enabled", func(t *testing.T) {
		config.CurrentConfig().SetSnykCodeEnabled(true)
		apiClient.ApiError = nil
		apiClient.CodeEnabled = true
		apiClient.LocalCodeEngineEnabled = true

		enabled := scanner.isSastEnabled()

		assert.False(t, enabled)
	})

	t.Run("should send a warning notification if Snyk Code Local Engine is enabled", func(t *testing.T) {
		apiClient.CodeEnabled = true
		apiClient.LocalCodeEngineEnabled = true
		apiClient.ApiError = nil
		notifier := notification.NewNotifier()
		// overwrite scanner, as we want our separate notifier
		scanner := &Scanner{
			SnykApiClient: apiClient,
			errorReporter: error_reporting.NewTestErrorReporter(),
			notifier:      notifier,
		}
		config.CurrentConfig().SetSnykCodeEnabled(true)
		channel := make(chan any)
		notifier.CreateListener(func(params any) {
			channel <- params
		})
		defer notifier.DisposeListener()
		expectedNotification := sglsp.ShowMessageParams{Type: sglsp.Warning, Message: localCodeEngineWarning}

		scanner.isSastEnabled()

		assert.Eventuallyf(
			t,
			func() bool { return expectedNotification == <-channel },
			5*time.Second,
			time.Millisecond,
			"expected warning notification",
		)
	})

	t.Run("should send a ShowMessageRequest notification if Snyk Code is enabled and the API returns false",
		func(t *testing.T) {
			apiClient.CodeEnabled = false
			apiClient.LocalCodeEngineEnabled = false
			apiClient.ApiError = nil
			config.CurrentConfig().SetSnykCodeEnabled(true)
			notifier := notification.NewNotifier()
			// overwrite scanner, as we want our separate notifier
			scanner := &Scanner{
				SnykApiClient: apiClient,
				errorReporter: error_reporting.NewTestErrorReporter(),
				notifier:      notifier,
			}
			actionMap := data_structure.NewOrderedMap[snyk.MessageAction, snyk.Command]()

			data, err := command.CreateFromCommandData(
				snyk.CommandData{
					Title:     snyk.OpenBrowserCommand,
					CommandId: snyk.OpenBrowserCommand,
					Arguments: []any{getCodeEnablementUrl()},
				},
				nil,
				nil,
				nil,
				notifier,
			)
			assert.NoError(t, err)

			actionMap.Add(enableSnykCodeMessageActionItemTitle, data)
			actionMap.Add(closeMessageActionItemTitle, nil)
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

			scanner.isSastEnabled()

			assert.Equal(t, expectedShowMessageRequest, <-channel)
		})
}
