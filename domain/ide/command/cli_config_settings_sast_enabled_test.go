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

	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
)

func Test_ApiClient_isCalledAndResultReturned(t *testing.T) {
	fakeApiClient := &snyk_api.FakeApiClient{
		CodeEnabled:            true,
		LocalCodeEngineEnabled: false,
	}

	configSettingsSastEnabled := cliConfigSettingsSastEnabled{apiClient: fakeApiClient}

	result, _ := configSettingsSastEnabled.Execute(context.Background())

	assert.True(t, result.(bool))
}

func Test_ApiClient_ReturnsFalseIfLocalCodeEngineIsEnabled(t *testing.T) {
	fakeApiClient := &snyk_api.FakeApiClient{
		CodeEnabled:            true,
		LocalCodeEngineEnabled: true,
	}

	configSettingsSastEnabled := cliConfigSettingsSastEnabled{apiClient: fakeApiClient}

	result, _ := configSettingsSastEnabled.Execute(context.Background())

	assert.False(t, result.(bool))
}

func Test_ApiClient_isCalledAndErrorReturned(t *testing.T) {
	apiError := snyk_api.NewSnykApiError("oh oh. an error", 500)
	fakeApiClient := &snyk_api.FakeApiClient{
		ApiError:    apiError,
		CodeEnabled: true,
	}

	configSettingsSastEnabled := cliConfigSettingsSastEnabled{apiClient: fakeApiClient}

	result, err := configSettingsSastEnabled.Execute(context.Background())

	assert.Error(t, err)
	assert.Equal(t, apiError, err)
	assert.False(t, result.(bool))
}
