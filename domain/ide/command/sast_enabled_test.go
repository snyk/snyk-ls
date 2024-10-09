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

package command

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_ApiClient_isCalledAndResultReturned(t *testing.T) {
	c := testutil.UnitTest(t)
	fakeApiClient := &snyk_api.FakeApiClient{
		CodeEnabled: true,
		LocalCodeEngine: snyk_api.LocalCodeEngine{
			Enabled: false,
		},
	}

	sastEnabledCmd := setupSastEnabledCommand(t, c, fakeApiClient)

	result, _ := sastEnabledCmd.Execute(context.Background())

	assert.True(t, result.(snyk_api.SastResponse).SastEnabled)
}

func setupSastEnabledCommand(t *testing.T, c *config.Config, fakeApiClient *snyk_api.FakeApiClient) sastEnabled {
	t.Helper()
	provider := authentication.NewFakeCliAuthenticationProvider(c)
	provider.IsAuthenticated = true

	sastEnabledCmd := sastEnabled{
		apiClient: fakeApiClient,
		authenticationService: authentication.NewAuthenticationService(
			c,
			provider,
			error_reporting.NewTestErrorReporter(),
			notification.NewMockNotifier(),
		),
	}
	return sastEnabledCmd
}

func Test_ApiClient_ReturnsTrueIfLocalCodeEngineIsEnabled(t *testing.T) {
	c := testutil.UnitTest(t)
	fakeApiClient := &snyk_api.FakeApiClient{
		CodeEnabled: true,
		LocalCodeEngine: snyk_api.LocalCodeEngine{
			Enabled: true,
		},
	}

	sastEnabledCmd := setupSastEnabledCommand(t, c, fakeApiClient)

	result, _ := sastEnabledCmd.Execute(context.Background())

	assert.True(t, result.(snyk_api.SastResponse).LocalCodeEngine.Enabled)
	assert.True(t, result.(snyk_api.SastResponse).SastEnabled)
}

func Test_ApiClient_isCalledAndErrorReturned(t *testing.T) {
	c := testutil.UnitTest(t)
	apiError := snyk_api.NewSnykApiError("oh oh. an error", 500)
	fakeApiClient := &snyk_api.FakeApiClient{
		ApiError:    apiError,
		CodeEnabled: true,
	}

	sastEnabledCmd := setupSastEnabledCommand(t, c, fakeApiClient)

	result, err := sastEnabledCmd.Execute(context.Background())

	assert.Error(t, err)
	assert.Equal(t, apiError, err)
	assert.False(t, result.(snyk_api.SastResponse).SastEnabled)
}
