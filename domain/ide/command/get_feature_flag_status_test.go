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
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_ApiClient_FeatureFlagIsEnabled(t *testing.T) {
	c := testutil.UnitTest(t)

	// Arrange
	expectedResponse := snyk_api.FFResponse{Ok: true}

	fakeApiClient := &snyk_api.FakeApiClient{}
	fakeApiClient.SetResponse("FeatureFlagStatus", expectedResponse)

	featureFlagStatusCmd := setupFeatureFlagCommand(t, c, fakeApiClient)

	// Execute the command
	result, err := featureFlagStatusCmd.Execute(context.Background())

	// Assert
	assert.NoError(t, err)
	ffResponse, ok := result.(snyk_api.FFResponse)
	assert.True(t, ok)
	assert.True(t, ffResponse.Ok)
}

func setupFeatureFlagCommand(t *testing.T, c *config.Config, fakeApiClient *snyk_api.FakeApiClient) featureFlagStatus {
	t.Helper()
	provider := authentication.NewFakeCliAuthenticationProvider(c)
	provider.IsAuthenticated = true

	// Pass the featureFlagType to the command
	featureFlagStatusCmd := featureFlagStatus{
		apiClient: fakeApiClient,
		command:   types.CommandData{Arguments: []interface{}{"snykCodeConsistentIgnores"}},
		authenticationService: authentication.NewAuthenticationService(
			c,
			provider,
			error_reporting.NewTestErrorReporter(),
			notification.NewMockNotifier(),
		),
	}
	return featureFlagStatusCmd
}
