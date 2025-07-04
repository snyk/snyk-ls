/*
 * © 2022 Snyk Limited All rights reserved.
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

package config

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/snyk/snyk-ls/internal/util"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/snyk/snyk-ls/infrastructure/cli/cli_constants"
	"github.com/snyk/snyk-ls/internal/types"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

func TestSetToken(t *testing.T) {
	t.Run("Legacy Token authentication", func(t *testing.T) {
		token := uuid.New().String()
		config := New()
		SetCurrentConfig(config)
		config.SetToken(token)
		assert.Equal(t, config.Token(), token)
		assert.NotEqual(t, config.Engine().GetConfiguration().Get(auth.CONFIG_KEY_OAUTH_TOKEN), token)
		assert.Equal(t, config.Engine().GetConfiguration().Get(configuration.AUTHENTICATION_TOKEN), token)
	})
	t.Run("OAuth Token authentication", func(t *testing.T) {
		config := New()
		SetCurrentConfig(config)
		config.authenticationMethod = types.OAuthAuthentication
		marshal, err := json.Marshal(oauth2.Token{AccessToken: t.Name()})
		assert.NoError(t, err)
		oauthString := string(marshal)

		config.SetToken(oauthString)

		assert.Equal(t, oauthString, config.Token())
		assert.Equal(t, oauthString, config.Engine().GetConfiguration().Get(auth.CONFIG_KEY_OAUTH_TOKEN))
	})
}

func TestConfigDefaults(t *testing.T) {
	c := New()

	assert.True(t, c.IsErrorReportingEnabled(), "Error Reporting should be enabled by default")
	assert.False(t, c.IsSnykAdvisorEnabled(), "Advisor should be disabled by default")
	assert.False(t, c.IsSnykCodeEnabled(), "Snyk Code should be disabled by default")
	assert.False(t, c.IsDeltaFindingsEnabled(), "Delta Findings should be disabled by default")
	assert.True(t, c.IsSnykOssEnabled(), "Snyk Open Source should be enabled by default")
	assert.True(t, c.IsSnykIacEnabled(), "Snyk IaC should be enabled by default")
	assert.Equal(t, "", c.LogPath(), "Logpath should be empty by default")
	assert.Equal(t, "md", c.Format(), "Message format should be md by default")
	assert.Equal(t, types.DefaultSeverityFilter(), c.FilterSeverity(), "All severities should be enabled by default")
	assert.Equal(t, types.DefaultIssueViewOptions(), c.IssueViewOptions(), "Only open issues should be shown by default")
	assert.Empty(t, c.trustedFolders)
	assert.Equal(t, types.TokenAuthentication, c.authenticationMethod)
}

func Test_TokenChanged_ChannelsInformed(t *testing.T) {
	// Arrange
	c := New()
	tokenChangedChannel := c.TokenChangesChannel()

	// Act
	// There's a 1 in 5 undecillion (5 * 10^36) chance for a collision here so let's hold our fingers
	c.SetToken(uuid.New().String())

	// Assert
	// This will either pass the test or fail by deadlock immediately if SetToken did not write to the change channels,
	// therefore there's no need for assert.Eventually
	assert.Eventuallyf(t, func() bool {
		<-tokenChangedChannel
		return true
	}, 5*time.Second, time.Millisecond, "Expected token changes channel to be informed, but it was not")
}

func Test_TokenChangedToSameToken_ChannelsNotInformed(t *testing.T) {
	// Arrange
	c := New()
	tokenChangedChannel := c.TokenChangesChannel()
	token := c.Token()

	// Act
	c.SetToken(token)

	// Assert
	select {
	case newToken := <-tokenChangedChannel:
		assert.Fail(t, "Expected empty token changes channel, but received new token (%v)", newToken)
	default:
		// This case triggers when tokenChangedChannel is empty, test passes
	}
}

func Test_SnykCodeAnalysisTimeoutReturnsTimeoutFromEnvironment(t *testing.T) {
	t.Setenv(snykCodeTimeoutKey, "1s")
	duration, _ := time.ParseDuration("1s")
	c := CurrentConfig()

	assert.Equal(t, duration, c.snykCodeAnalysisTimeoutFromEnv())
}

func Test_SnykCodeAnalysisTimeoutReturnsDefaultIfNoEnvVariableFound(t *testing.T) {
	t.Setenv(snykCodeTimeoutKey, "")
	c := CurrentConfig()

	assert.Equal(t, 12*time.Hour, c.snykCodeAnalysisTimeoutFromEnv())
}

func TestSnykCodeApi(t *testing.T) {
	t.Run("endpoint not provided", func(t *testing.T) {
		codeApiEndpoint, _ := getCodeApiUrlFromCustomEndpoint("")
		assert.Equal(t, "https://deeproxy.snyk.io", codeApiEndpoint)
	})

	t.Run("endpoint provided without 'app' prefix", func(t *testing.T) {
		endpoint := "https://snyk.io/api/v1"
		codeApiEndpoint, _ := getCodeApiUrlFromCustomEndpoint(endpoint)
		assert.Equal(t, "https://deeproxy.snyk.io", codeApiEndpoint)
	})

	t.Run("endpoint provided with 'app' prefix with v1 suffix", func(t *testing.T) {
		endpoint := "https://app.snyk.io/api/v1"
		codeApiEndpoint, _ := getCodeApiUrlFromCustomEndpoint(endpoint)
		assert.Equal(t, "https://deeproxy.snyk.io", codeApiEndpoint)
	})

	t.Run("endpoint provided with 'app' prefix without v1 suffix", func(t *testing.T) {
		endpoint := "https://app.snyk.io/api"
		codeApiEndpoint, _ := getCodeApiUrlFromCustomEndpoint(endpoint)
		assert.Equal(t, "https://deeproxy.snyk.io", codeApiEndpoint)
	})

	t.Run("endpoint provided with 'api' prefix", func(t *testing.T) {
		endpoint := "https://api.snyk.io"
		codeApiEndpoint, _ := getCodeApiUrlFromCustomEndpoint(endpoint)
		assert.Equal(t, "https://deeproxy.snyk.io", codeApiEndpoint)
	})

	t.Run("proxy endpoint provided via 'DEEPROXY_API_URL' environment variable", func(t *testing.T) {
		customDeeproxyUrl := "https://deeproxy.custom.url.snyk.io"
		t.Setenv("DEEPROXY_API_URL", customDeeproxyUrl)
		codeApiEndpoint, _ := getCodeApiUrlFromCustomEndpoint("")
		assert.Equal(t, customDeeproxyUrl, codeApiEndpoint)
	})
}

func Test_SetSeverityFilter(t *testing.T) {
	t.Run("Saves filter", func(t *testing.T) {
		c := New()
		c.SetSeverityFilter(util.Ptr(types.NewSeverityFilter(true, true, false, false)))
		assert.Equal(t, types.NewSeverityFilter(true, true, false, false), c.FilterSeverity())
	})

	t.Run("Returns correctly", func(t *testing.T) {
		c := New()
		lowExcludedFilter := types.NewSeverityFilter(true, true, false, false)

		modified := c.SetSeverityFilter(&lowExcludedFilter)
		assert.True(t, modified)

		modified = c.SetSeverityFilter(&lowExcludedFilter)
		assert.False(t, modified)
	})
}

func Test_SetIssueViewOptions(t *testing.T) {
	t.Run("Saves filter", func(t *testing.T) {
		c := New()
		c.SetIssueViewOptions(util.Ptr(types.NewIssueViewOptions(false, true)))
		assert.Equal(t, types.NewIssueViewOptions(false, true), c.IssueViewOptions())
	})

	t.Run("Returns correctly", func(t *testing.T) {
		c := New()
		ignoredOnlyFilter := types.NewIssueViewOptions(false, true)

		modified := c.SetIssueViewOptions(&ignoredOnlyFilter)
		assert.True(t, modified)

		modified = c.SetIssueViewOptions(&ignoredOnlyFilter)
		assert.False(t, modified)
	})
}

func Test_ManageBinariesAutomatically(t *testing.T) {
	c := New()

	// case: standalone, manage true
	c.SetManageBinariesAutomatically(true)
	assert.True(t, c.ManageBinariesAutomatically())
	assert.True(t, c.ManageCliBinariesAutomatically())

	// case: standalone, manage false
	c.SetManageBinariesAutomatically(false)
	assert.False(t, c.ManageBinariesAutomatically())
	assert.False(t, c.ManageCliBinariesAutomatically())

	// case: extension, manage true
	c.SetManageBinariesAutomatically(true)
	c.Engine().GetConfiguration().Set(cli_constants.EXECUTION_MODE_KEY, cli_constants.EXECUTION_MODE_VALUE_EXTENSION)
	assert.True(t, c.ManageBinariesAutomatically())
	assert.False(t, c.ManageCliBinariesAutomatically())
}

func Test_IsFedramp(t *testing.T) {
	t.Run("short hostname", func(t *testing.T) {
		c := New()
		c.UpdateApiEndpoints("https://api.snyk.io")
		assert.False(t, c.IsFedramp())
	})

	t.Run("fedramp hostname", func(t *testing.T) {
		c := New()
		c.UpdateApiEndpoints("https://api.fedramp.snykgov.io")
		assert.True(t, c.IsFedramp())
	})

	t.Run("non-fedramp hostname", func(t *testing.T) {
		c := New()
		c.UpdateApiEndpoints("https://api.fedddddddddramp.snykgov.io")
		assert.True(t, c.IsFedramp())
	})
}

func Test_IsAnalyticsPermitted(t *testing.T) {
	t.Run("Analytics not permitted for EU app", func(t *testing.T) {
		c := New()
		assert.True(t, c.UpdateApiEndpoints("https://app.eu.snyk.io/api"))
		assert.False(t, c.IsAnalyticsPermitted())
	})

	t.Run("Analytics not permitted for EU api", func(t *testing.T) {
		c := New()
		assert.True(t, c.UpdateApiEndpoints("https://api.eu.snyk.io"))
		assert.False(t, c.IsAnalyticsPermitted())
	})

	t.Run("Analytics permitted hostname", func(t *testing.T) {
		c := New()
		assert.True(t, c.UpdateApiEndpoints("https://app.snyk.io/api"))
		assert.True(t, c.IsAnalyticsPermitted())
	})

	t.Run("Analytics permitted US hostname", func(t *testing.T) {
		c := New()
		assert.True(t, c.UpdateApiEndpoints("https://app.us.snyk.io/api"))
		assert.True(t, c.IsAnalyticsPermitted())
	})
}

func TestSnykUiEndpoint(t *testing.T) {
	c := New()
	t.Run("Default Api Endpoint with /api prefix", func(t *testing.T) {
		uiEndpoint := c.SnykUI()
		assert.Equal(t, "https://app.snyk.io", uiEndpoint)
	})

	t.Run("API endpoint provided without 'app' prefix", func(t *testing.T) {
		apiEndpoint := "https://snyk.io/api/v1"
		c.UpdateApiEndpoints(apiEndpoint)
		uiEndpoint := c.SnykUI()
		assert.Equal(t, "https://app.snyk.io", uiEndpoint)
	})

	t.Run("API endpoint provided with 'app' prefix with v1 suffix", func(t *testing.T) {
		apiEndpoint := "https://app.snyk.io/api/v1"
		c.UpdateApiEndpoints(apiEndpoint)
		uiEndpoint := c.SnykUI()
		assert.Equal(t, "https://app.snyk.io", uiEndpoint)
	})

	t.Run("endpoint provided with 'app' prefix without v1 suffix", func(t *testing.T) {
		apiEndpoint := "https://app.snyk.io/api"
		c.UpdateApiEndpoints(apiEndpoint)
		uiEndpoint := c.SnykUI()
		assert.Equal(t, "https://app.snyk.io", uiEndpoint)
	})

	t.Run("Api endpoint provided with 'api' prefix", func(t *testing.T) {
		apiEndpoint := "https://api.snyk.io"
		c.UpdateApiEndpoints(apiEndpoint)
		uiEndpoint := c.SnykUI()
		assert.Equal(t, "https://app.snyk.io", uiEndpoint)
	})

	t.Run("Api endpoint provided with 'api' and 'eu' prefix", func(t *testing.T) {
		apiEndpoint := "https://api.eu.snyk.io"
		c.UpdateApiEndpoints(apiEndpoint)
		uiEndpoint := c.SnykUI()
		assert.Equal(t, "https://app.eu.snyk.io", uiEndpoint)
		assert.Equal(t, c.SnykUI(), c.engine.GetConfiguration().Get(configuration.WEB_APP_URL))
	})

	t.Run("Empty Api Endpoint should fall back to default and return default SnykUI Url", func(t *testing.T) {
		apiEndpoint := ""
		c.UpdateApiEndpoints(apiEndpoint)
		uiEndpoint := c.SnykUI()
		assert.Equal(t, "https://app.snyk.io", uiEndpoint)
	})

	t.Run("Fedramp API Endpoint provided with 'api' prefix", func(t *testing.T) {
		apiEndpoint := "https://api.fedramp.snykgov.io"
		c.UpdateApiEndpoints(apiEndpoint)
		uiEndpoint := c.SnykUI()
		assert.Equal(t, "https://app.fedramp.snykgov.io", uiEndpoint)
	})
}

func TestConfig_shouldUpdateOAuth2Token(t *testing.T) {
	// add test cases
	c := New()

	token := oauth2.Token{
		AccessToken:  "a",
		RefreshToken: "b",
		Expiry:       time.Now().Add(time.Hour),
	}

	newTokenBytes, err := json.Marshal(token)
	require.NoError(t, err)

	t.Run("old token empty -> true", func(t *testing.T) {
		assert.True(t, c.shouldUpdateOAuth2Token("", string(newTokenBytes)))
	})
	t.Run("new token empty -> true", func(t *testing.T) {
		assert.True(t, c.shouldUpdateOAuth2Token(string(newTokenBytes), ""))
	})
	t.Run("both tokens empty -> false", func(t *testing.T) {
		assert.True(t, c.shouldUpdateOAuth2Token("", ""))
	})
	t.Run("old token expires after new token -> false", func(t *testing.T) {
		oldToken := token
		oldToken.Expiry = token.Expiry.Add(time.Hour)
		oldTokenBytes, err := json.Marshal(oldToken)
		require.NoError(t, err)

		assert.False(t, c.shouldUpdateOAuth2Token(string(oldTokenBytes), string(newTokenBytes)))
	})
	t.Run("old token expires before new token -> true", func(t *testing.T) {
		oldToken := token
		oldToken.Expiry = token.Expiry.Add(-time.Hour)
		oldTokenBytes, err := json.Marshal(oldToken)
		require.NoError(t, err)

		assert.True(t, c.shouldUpdateOAuth2Token(string(oldTokenBytes), string(newTokenBytes)))
	})
	t.Run("old token not an oauth token, but new one is -> true", func(t *testing.T) {
		assert.True(t, c.shouldUpdateOAuth2Token(uuid.NewString(), string(newTokenBytes)))
	})
	t.Run("new token not an oauth token -> false", func(t *testing.T) {
		assert.False(t, c.shouldUpdateOAuth2Token(string(newTokenBytes), uuid.NewString()))
	})
}

func TestConfig_AuthenticationMethodMatchesToken(t *testing.T) {
	// Dummy tokens. Note that these were created using random characters, but follow the same format as real tokens.
	oAuthToken := "{\"access_token\":\"eyJhbHciOiJSUzI1NiIsIqtpZCI7IjQ2ZWNjOTI1IiwiEHlwIjoiSlEUIn0.eyJhEWQiOlsiaHR0cHq" +
		"7Ly9hcHkuZHV2LnNueWsuaW8iXSwiYXpwIjoiYjU2ZERjqqUtYjllqS00ZEI3LTH3NzqtYWQ0N2VhZqIwOTU2IiwiZXhwIjoxNzQ4NEQ4Njq5LCJ" +
		"pYXQiOjE3NEH0NEUwqzksIqlzcyI7Iqh0EHBzOi8vYXBwcy5kZXYuc255ay5pbyIsIqp0aSI7IjI1ZHU5N2Y3LWQ0qEYtNEJiNi04Yqq5LTQzqEF" +
		"jOHQ0Y2QyNCIsInNjb3BlIjoib3JnLnJlYWQiLCJzEWIiOiJkYTA0N2EwYy04OHE1LTQ1YqQtOHQxZi1hOEHzOEc5qzliqEHifQ.I1YANnQvkLWj" +
		"WkqQk77LKUP41xKAcqHyoN7UTTYE2q82qtuHaes9oLpjJUHnq_qaBHHW_qviVEIRNquHuYR8A9BHnws-wL5VAqSHsrErrNStQjFHPXRnWti2qOHq" +
		"qub1q9EqCnukEIeFsWe5aK3K-5nB3qEf44sSt9YN-1Sw7uCbaWKR7H8cHwfnJF2H0jfoo4qTQqV3oHZWhj01LE1_xzvncfl8EuvOa7IrtqcEq9O3" +
		"4L9WqUH4HJOuxwxLEqOne7TECaqVqapSXE_f7sQ_nJH2jqqaJEAN8Hf4ZNWxR8HntStY91EcozP7InFAeZY8lOH7u3Xi7kiX4qvJ9_w0JA\"," +
		"\"token_type\":\"bearer\",\"refresh_token\":" +
		"\"snyk_rt_Y8EwxzIhpqCWhWScsOj-QCEHyEWbVJsYetH4E2lZi7s.kQ7cpop4tp7EJn-8e7OQRT2lqri0Fw1LqiK_boXqLB8_v1\"," +
		"\"expiry\":\"1970-01-01T00:00:00.000000+00:00\"}"
	apiToken := "e24850f4-c252-4813-b37e-21825873038e"
	personalAccessToken := "snyk_uat.1fcad39e.eyJlJjoxNzQ4NDMxNjJwLCJoJjoJc244ay4payJsJmsoJOJJaWmNXcFdkcjRGamhOYjYxUWdk" +
		"REJaJJwJcyJ6JnE2RGRfUzU2UUpXT0otWVRYVDAwcWcJfQ.-q0jjlMEo4oqT3oga7Y-4Eq0NHqDfEDnWQZSrkv_ea162aHvwHMe9Decpz3JYO21r" +
		"7DOTfne4FF0Y3C8cjJFCw"
	emptyToken := ""

	// Note we're deliberately omitting types.FakeAuthentication; we append it below
	tokenMap := map[types.AuthenticationMethod]string{
		types.OAuthAuthentication:       oAuthToken,
		types.TokenAuthentication:       apiToken,
		types.PatAuthentication:         personalAccessToken,
		types.EmptyAuthenticationMethod: emptyToken,
	}

	// Config should be initialized with an empty token, but using the Token authentication type.
	c := New()
	assert.False(t, c.AuthenticationMethodMatchesToken())

	for _, method := range append(slices.Collect(maps.Keys(tokenMap)), types.FakeAuthentication) {
		c.SetAuthenticationMethod(method)
		for tokenType, token := range tokenMap {
			c.token = token
			// Fake authentication should allow any token type, otherwise the authentication method must match.
			shouldMatch := method == tokenType || method == types.FakeAuthentication
			t.Run(fmt.Sprintf("method: %s, token type: %s -> %t", method, tokenType, shouldMatch), func(t *testing.T) {
				if shouldMatch {
					assert.True(t, c.AuthenticationMethodMatchesToken())
				} else {
					assert.False(t, c.AuthenticationMethodMatchesToken())
				}
			})
		}
	}
}
