/*
 * © 2025 Snyk Limited
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

package authentication

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/stretchr/testify/assert"
)

func TestPatAuthenticationProvider_AuthURL(t *testing.T) {
	tests := []struct {
		name        string
		expectedUrl string
	}{
		{
			name:        "Specify URL",
			expectedUrl: "https://test.snyk.test",
		},
		{
			name:        "Blank URL",
			expectedUrl: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &PatAuthenticationProvider{
				config:  mocks.NewMockConfiguration(gomock.NewController(t)),
				authURL: tt.expectedUrl,
				logger:  &zerolog.Logger{},
			}
			assert.Equalf(t, tt.expectedUrl, p.AuthURL(context.Background()), "AuthURL(nil)")
		})
	}
}

func TestPatAuthenticationProvider_Authenticate(t *testing.T) {
	testUrl := "https://test.snyk.test"
	expectedUrl := testUrl + "/account/personal-access-tokens"

	ctrl := gomock.NewController(t)
	mockConfiguration := mocks.NewMockConfiguration(ctrl)
	urlPassedToBrowserFunction := ""
	openBrowserFunction := func(url string) {
		urlPassedToBrowserFunction = url
	}

	mockConfiguration.EXPECT().GetString(configuration.WEB_APP_URL).Return(testUrl)

	p := &PatAuthenticationProvider{
		config:          mockConfiguration,
		openBrowserFunc: openBrowserFunction,
		logger:          &zerolog.Logger{},
	}

	got, err := p.Authenticate(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, "", got, "Authenticate() returns blank token string")
	assert.Equal(t, expectedUrl, urlPassedToBrowserFunction, "Authenticate() calls browser function")
}

func TestPatAuthenticationProvider_ClearAuthentication(t *testing.T) {
	config := configuration.New()
	config.Set(auth.CONFIG_KEY_OAUTH_TOKEN, "oauth_token")
	config.Set(configuration.AUTHENTICATION_TOKEN, "auth_token")
	config.Set(configuration.AUTHENTICATION_BEARER_TOKEN, "auth_bearer_token")

	p := &PatAuthenticationProvider{
		config: config,
		logger: &zerolog.Logger{},
	}

	assert.NotEmpty(t, p.config.Get(auth.CONFIG_KEY_OAUTH_TOKEN))
	assert.NotEmpty(t, p.config.Get(configuration.AUTHENTICATION_TOKEN))
	assert.NotEmpty(t, p.config.Get(configuration.AUTHENTICATION_BEARER_TOKEN))

	err := p.ClearAuthentication(context.Background())
	assert.NoError(t, err)
	assert.Empty(t, p.config.Get(auth.CONFIG_KEY_OAUTH_TOKEN))
	assert.Empty(t, p.config.Get(configuration.AUTHENTICATION_TOKEN))
	assert.Empty(t, p.config.Get(configuration.AUTHENTICATION_BEARER_TOKEN))
}

func TestPatAuthenticationProvider_GetCheckAuthenticationFunction(t *testing.T) {
	p := &PatAuthenticationProvider{}

	// GetCheckAuthenticationFunction should return AuthenticationCheck()
	user, err := p.GetCheckAuthenticationFunction()()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get active user:")
	assert.Equal(t, "", user, "GetCheckAuthenticationFunction()")
}

func TestPatAuthenticationProvider_setAuthUrl(t *testing.T) {
	p := &PatAuthenticationProvider{
		logger: &zerolog.Logger{},
	}
	assert.Empty(t, p.AuthURL(context.Background()))

	p.setAuthUrl("https://test.snyk.test")
	assert.Equal(t, "https://test.snyk.test", p.AuthURL(context.Background()))
}

func Test_newPatAuthenticationProvider(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockConfiguration := mocks.NewMockConfiguration(ctrl)

	urlPassedToBrowserFunction := ""
	openBrowserFunction := func(url string) {
		urlPassedToBrowserFunction = url
	}

	testUrl := "https://test.snyk.test"

	p := newPatAuthenticationProvider(mockConfiguration, openBrowserFunction, &zerolog.Logger{})
	p.openBrowserFunc(testUrl)

	assert.Equal(t, p.config, mockConfiguration)
	assert.Equal(t, testUrl, urlPassedToBrowserFunction)
	assert.Empty(t, p.AuthURL(context.Background()))
}
