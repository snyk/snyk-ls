/*
 * © 2022-2026 Snyk Limited All rights reserved.
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
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"

	"github.com/snyk/snyk-ls/infrastructure/cli/cli_constants"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

func initEngineForConfigTest(t *testing.T) (workflow.Engine, *TokenServiceImpl) {
	t.Helper()
	return initEngineForConfigPackageTests(t, []string{})
}

// defaultConfigResolverForTest creates a ConfigResolver wired to the engine's configuration.
// Inlined to avoid import cycle (testutil imports config).
func defaultConfigResolverForTest(engine workflow.Engine) *types.ConfigResolver {
	gafConf := engine.GetConfiguration()
	logger := engine.GetLogger()
	fs := pflag.NewFlagSet("config-test", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	_ = gafConf.AddFlagSet(fs)
	fm := workflow.ConfigurationOptionsFromFlagset(fs)
	resolver := types.NewConfigResolver(logger)
	resolver.SetPrefixKeyResolver(configresolver.New(gafConf, fm), gafConf, fm)
	return resolver
}

func TestSetToken(t *testing.T) {
	t.Run("Legacy Token authentication", func(t *testing.T) {
		engine, ts := initEngineForConfigTest(t)
		token := uuid.New().String()
		ts.SetToken(engine.GetConfiguration(), token)
		assert.Equal(t, GetToken(engine.GetConfiguration()), token)
		assert.NotEqual(t, engine.GetConfiguration().Get(auth.CONFIG_KEY_OAUTH_TOKEN), token)
		assert.Equal(t, engine.GetConfiguration().Get(configuration.AUTHENTICATION_TOKEN), token)
	})
	t.Run("OAuth Token authentication", func(t *testing.T) {
		engine, ts := initEngineForConfigTest(t)
		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.OAuthAuthentication))
		marshal, err := json.Marshal(oauth2.Token{AccessToken: t.Name()})
		assert.NoError(t, err)
		oauthString := string(marshal)

		ts.SetToken(engine.GetConfiguration(), oauthString)

		assert.Equal(t, oauthString, GetToken(engine.GetConfiguration()))
		assert.Equal(t, oauthString, engine.GetConfiguration().Get(auth.CONFIG_KEY_OAUTH_TOKEN))
	})
}

func TestConfigDefaults(t *testing.T) {
	engine, _ := initEngineForConfigTest(t)
	conf := engine.GetConfiguration()

	assert.True(t, types.GetGlobalBool(conf, types.SettingSendErrorReports), "Error Reporting should be enabled by default")
	assert.False(t, types.GetGlobalBool(conf, types.SettingSnykAdvisorEnabled), "Advisor should be disabled by default")
	assert.False(t, types.GetGlobalBool(conf, types.SettingSnykCodeEnabled), "Snyk Code should be disabled by default")
	assert.False(t, types.GetGlobalBool(conf, types.SettingScanNetNew), "Delta Findings should be disabled by default")
	assert.True(t, types.GetGlobalBool(conf, types.SettingSnykOssEnabled), "Snyk Open Source should be enabled by default")
	assert.True(t, types.GetGlobalBool(conf, types.SettingSnykIacEnabled), "Snyk IaC should be enabled by default")
	assert.Equal(t, "", conf.GetString(configresolver.UserGlobalKey(types.SettingLogPath)), "Logpath should be empty by default")
	assert.Equal(t, "md", types.GetGlobalString(conf, types.SettingFormat), "Message format should be md by default")
	assert.Equal(t, types.DefaultSeverityFilter(), GetFilterSeverity(conf), "All severities should be enabled by default")
	assert.Equal(t, types.DefaultIssueViewOptions(), GetIssueViewOptions(conf), "Only open issues should be shown by default")
	val, _ := conf.Get(configresolver.UserGlobalKey(types.SettingTrustedFolders)).([]types.FilePath)
	assert.Empty(t, val)
	assert.Equal(t, types.OAuthAuthentication, GetAuthenticationMethodFromConfig(conf))
}

func Test_SetEngineDefaults_DoNotMarkDefaultsAsUserSet(t *testing.T) {
	// Defaults registered via AddDefaultValue must NOT be marked as user-set.
	// If IsSet returns true, the config resolver treats them as explicit user values and
	// LDX-Sync remote config can no longer override them via the precedence chain.
	engine, _ := initEngineForConfigTest(t)
	conf := engine.GetConfiguration()

	assert.False(t, conf.IsSet(configresolver.UserGlobalKey(types.SettingSnykOssEnabled)), "SnykOss default must not be marked user-set")
	assert.False(t, conf.IsSet(configresolver.UserGlobalKey(types.SettingSnykIacEnabled)), "SnykIac default must not be marked user-set")
	assert.False(t, conf.IsSet(configresolver.UserGlobalKey(types.SettingAutomaticDownload)), "AutomaticDownload default must not be marked user-set")
	assert.False(t, conf.IsSet(configresolver.UserGlobalKey(types.SettingAuthenticationMethod)), "AuthenticationMethod default must not be marked user-set")
	assert.False(t, conf.IsSet(configresolver.UserGlobalKey(types.SettingAutomaticAuthentication)), "AutomaticAuthentication default must not be marked user-set")
	assert.False(t, conf.IsSet(configresolver.UserGlobalKey(types.SettingTrustEnabled)), "TrustEnabled default must not be marked user-set")
	assert.False(t, conf.IsSet(configresolver.UserGlobalKey(types.SettingScanAutomatic)), "ScanAutomatic default must not be marked user-set")
}

func Test_TokenChanged_ChannelsInformed(t *testing.T) {
	// Arrange
	engine, ts := initEngineForConfigTest(t)
	tokenChangedChannel := ts.TokenChangesChannel()

	// Act
	// There's a 1 in 5 undecillion (5 * 10^36) chance for a collision here so let's hold our fingers
	ts.SetToken(engine.GetConfiguration(), uuid.New().String())

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
	engine, ts := initEngineForConfigTest(t)
	tokenChangedChannel := ts.TokenChangesChannel()
	token := GetToken(engine.GetConfiguration())

	// Act
	ts.SetToken(engine.GetConfiguration(), token)

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
	engine, _ := initEngineForConfigTest(t)

	assert.Equal(t, duration, SnykCodeAnalysisTimeoutFromEnv(engine.GetLogger()))
}

func Test_SnykCodeAnalysisTimeoutReturnsDefaultIfNoEnvVariableFound(t *testing.T) {
	t.Setenv(snykCodeTimeoutKey, "")
	engine, _ := initEngineForConfigTest(t)

	assert.Equal(t, 12*time.Hour, SnykCodeAnalysisTimeoutFromEnv(engine.GetLogger()))
}

func TestSnykCodeApi(t *testing.T) {
	engine, _ := initEngineForConfigTest(t)
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()
	t.Run("endpoint not provided", func(t *testing.T) {
		codeApiEndpoint, _ := GetCodeApiUrlFromCustomEndpoint(conf, nil, logger)

		assert.Equal(t, "https://deeproxy.snyk.io", codeApiEndpoint)
	})

	t.Run("endpoint provided without 'app' prefix", func(t *testing.T) {
		UpdateApiEndpointsOnConfig(conf, "https://snyk.io/api/v1")
		codeApiEndpoint, _ := GetCodeApiUrlFromCustomEndpoint(conf, nil, logger)
		assert.Equal(t, "https://deeproxy.snyk.io", codeApiEndpoint)
	})

	t.Run("endpoint provided with 'app' prefix with v1 suffix", func(t *testing.T) {
		UpdateApiEndpointsOnConfig(conf, "https://app.snyk.io/api/v1")
		codeApiEndpoint, _ := GetCodeApiUrlFromCustomEndpoint(conf, nil, logger)
		assert.Equal(t, "https://deeproxy.snyk.io", codeApiEndpoint)
	})

	t.Run("endpoint provided with 'app' prefix without v1 suffix", func(t *testing.T) {
		UpdateApiEndpointsOnConfig(conf, "https://app.snyk.io/api")
		codeApiEndpoint, _ := GetCodeApiUrlFromCustomEndpoint(conf, nil, logger)
		assert.Equal(t, "https://deeproxy.snyk.io", codeApiEndpoint)
	})

	t.Run("endpoint provided with 'api' prefix", func(t *testing.T) {
		UpdateApiEndpointsOnConfig(conf, "https://api.snyk.io")
		codeApiEndpoint, _ := GetCodeApiUrlFromCustomEndpoint(conf, nil, logger)
		assert.Equal(t, "https://deeproxy.snyk.io", codeApiEndpoint)
	})

	t.Run("proxy endpoint provided via 'DEEPROXY_API_URL' environment variable", func(t *testing.T) {
		customDeeproxyUrl := "https://deeproxy.custom.url.snyk.io"
		t.Setenv("DEEPROXY_API_URL", customDeeproxyUrl)
		codeApiEndpoint, _ := GetCodeApiUrlFromCustomEndpoint(conf, nil, logger)
		assert.Equal(t, customDeeproxyUrl, codeApiEndpoint)
	})
}

func Test_SetSeverityFilter(t *testing.T) {
	t.Run("Saves filter", func(t *testing.T) {
		engine, _ := initEngineForConfigTest(t)
		resolver := defaultConfigResolverForTest(engine)
		SetSeverityFilterOnConfig(engine.GetConfiguration(), util.Ptr(types.NewSeverityFilter(true, true, false, false)), engine.GetLogger(), resolver)
		assert.Equal(t, types.NewSeverityFilter(true, true, false, false), GetFilterSeverity(engine.GetConfiguration()))
	})

	t.Run("Returns correctly", func(t *testing.T) {
		engine, _ := initEngineForConfigTest(t)
		resolver := defaultConfigResolverForTest(engine)
		lowExcludedFilter := types.NewSeverityFilter(true, true, false, false)

		modified := SetSeverityFilterOnConfig(engine.GetConfiguration(), &lowExcludedFilter, engine.GetLogger(), resolver)
		assert.True(t, modified)

		modified = SetSeverityFilterOnConfig(engine.GetConfiguration(), &lowExcludedFilter, engine.GetLogger(), resolver)
		assert.False(t, modified)
	})
}

func Test_SetIssueViewOptions(t *testing.T) {
	t.Run("Saves filter", func(t *testing.T) {
		engine, _ := initEngineForConfigTest(t)
		resolver := defaultConfigResolverForTest(engine)
		SetIssueViewOptionsOnConfig(engine.GetConfiguration(), util.Ptr(types.NewIssueViewOptions(false, true)), engine.GetLogger(), resolver)
		assert.Equal(t, types.NewIssueViewOptions(false, true), GetIssueViewOptions(engine.GetConfiguration()))
	})

	t.Run("Returns correctly", func(t *testing.T) {
		engine, _ := initEngineForConfigTest(t)
		resolver := defaultConfigResolverForTest(engine)
		ignoredOnlyFilter := types.NewIssueViewOptions(false, true)

		modified := SetIssueViewOptionsOnConfig(engine.GetConfiguration(), &ignoredOnlyFilter, engine.GetLogger(), resolver)
		assert.True(t, modified)

		modified = SetIssueViewOptionsOnConfig(engine.GetConfiguration(), &ignoredOnlyFilter, engine.GetLogger(), resolver)
		assert.False(t, modified)
	})
}

func Test_ManageBinariesAutomatically(t *testing.T) {
	engine, _ := initEngineForConfigTest(t)
	conf := engine.GetConfiguration()

	// case: standalone, manage true
	conf.Set(configresolver.UserGlobalKey(types.SettingAutomaticDownload), true)
	assert.True(t, conf.GetBool(configresolver.UserGlobalKey(types.SettingAutomaticDownload)))
	assert.True(t, ManageCliBinariesAutomatically(conf))

	// case: standalone, manage false
	conf.Set(configresolver.UserGlobalKey(types.SettingAutomaticDownload), false)
	assert.False(t, conf.GetBool(configresolver.UserGlobalKey(types.SettingAutomaticDownload)))
	assert.False(t, ManageCliBinariesAutomatically(conf))

	// case: extension, manage true
	conf.Set(configresolver.UserGlobalKey(types.SettingAutomaticDownload), true)
	conf.Set(cli_constants.EXECUTION_MODE_KEY, cli_constants.EXECUTION_MODE_VALUE_EXTENSION)
	assert.True(t, conf.GetBool(configresolver.UserGlobalKey(types.SettingAutomaticDownload)))
	assert.False(t, ManageCliBinariesAutomatically(conf))
}

func Test_IsFedramp(t *testing.T) {
	t.Run("short hostname", func(t *testing.T) {
		engine, _ := initEngineForConfigTest(t)
		UpdateApiEndpointsOnConfig(engine.GetConfiguration(), "https://api.snyk.io")
		assert.False(t, engine.GetConfiguration().GetBool(configuration.IS_FEDRAMP))
	})

	t.Run("fedramp hostname", func(t *testing.T) {
		engine, _ := initEngineForConfigTest(t)
		UpdateApiEndpointsOnConfig(engine.GetConfiguration(), "https://api.fedramp.snykgov.io")
		assert.True(t, engine.GetConfiguration().GetBool(configuration.IS_FEDRAMP))
	})

	t.Run("non-fedramp hostname", func(t *testing.T) {
		engine, _ := initEngineForConfigTest(t)
		UpdateApiEndpointsOnConfig(engine.GetConfiguration(), "https://api.fedddddddddramp.snykgov.io")
		assert.True(t, engine.GetConfiguration().GetBool(configuration.IS_FEDRAMP))
	})
}

func Test_IsAnalyticsPermitted(t *testing.T) {
	t.Run("Analytics not permitted for EU app", func(t *testing.T) {
		engine, _ := initEngineForConfigTest(t)
		assert.True(t, UpdateApiEndpointsOnConfig(engine.GetConfiguration(), "https://app.eu.snyk.io/api"))
		assert.False(t, IsAnalyticsPermittedForAPI(engine.GetConfiguration().GetString(configuration.API_URL)))
	})

	t.Run("Analytics not permitted for EU api", func(t *testing.T) {
		engine, _ := initEngineForConfigTest(t)
		assert.True(t, UpdateApiEndpointsOnConfig(engine.GetConfiguration(), "https://api.eu.snyk.io"))
		assert.False(t, IsAnalyticsPermittedForAPI(engine.GetConfiguration().GetString(configuration.API_URL)))
	})

	t.Run("Analytics permitted hostname", func(t *testing.T) {
		engine, _ := initEngineForConfigTest(t)
		assert.True(t, UpdateApiEndpointsOnConfig(engine.GetConfiguration(), "https://app.snyk.io/api"))
		assert.True(t, IsAnalyticsPermittedForAPI(engine.GetConfiguration().GetString(configuration.API_URL)))
	})

	t.Run("Analytics permitted US hostname", func(t *testing.T) {
		engine, _ := initEngineForConfigTest(t)
		assert.True(t, UpdateApiEndpointsOnConfig(engine.GetConfiguration(), "https://app.us.snyk.io/api"))
		assert.True(t, IsAnalyticsPermittedForAPI(engine.GetConfiguration().GetString(configuration.API_URL)))
	})
}

func TestSnykUiEndpoint(t *testing.T) {
	engine, _ := initEngineForConfigTest(t)
	t.Run("Default Api Endpoint with /api prefix", func(t *testing.T) {
		uiEndpoint := GetSnykUI(engine.GetConfiguration())
		assert.Equal(t, "https://app.snyk.io", uiEndpoint)
	})

	t.Run("API endpoint provided without 'app' prefix", func(t *testing.T) {
		apiEndpoint := "https://snyk.io/api/v1"
		UpdateApiEndpointsOnConfig(engine.GetConfiguration(), apiEndpoint)
		uiEndpoint := GetSnykUI(engine.GetConfiguration())
		assert.Equal(t, "https://app.snyk.io", uiEndpoint)
	})

	t.Run("API endpoint provided with 'app' prefix with v1 suffix", func(t *testing.T) {
		apiEndpoint := "https://app.snyk.io/api/v1"
		UpdateApiEndpointsOnConfig(engine.GetConfiguration(), apiEndpoint)
		uiEndpoint := GetSnykUI(engine.GetConfiguration())
		assert.Equal(t, "https://app.snyk.io", uiEndpoint)
	})

	t.Run("endpoint provided with 'app' prefix without v1 suffix", func(t *testing.T) {
		apiEndpoint := "https://app.snyk.io/api"
		UpdateApiEndpointsOnConfig(engine.GetConfiguration(), apiEndpoint)
		uiEndpoint := GetSnykUI(engine.GetConfiguration())
		assert.Equal(t, "https://app.snyk.io", uiEndpoint)
	})

	t.Run("Api endpoint provided with 'api' prefix", func(t *testing.T) {
		apiEndpoint := "https://api.snyk.io"
		UpdateApiEndpointsOnConfig(engine.GetConfiguration(), apiEndpoint)
		uiEndpoint := GetSnykUI(engine.GetConfiguration())
		assert.Equal(t, "https://app.snyk.io", uiEndpoint)
	})

	t.Run("Api endpoint provided with 'api' and 'eu' prefix", func(t *testing.T) {
		apiEndpoint := "https://api.eu.snyk.io"
		UpdateApiEndpointsOnConfig(engine.GetConfiguration(), apiEndpoint)
		uiEndpoint := GetSnykUI(engine.GetConfiguration())
		assert.Equal(t, "https://app.eu.snyk.io", uiEndpoint)
		assert.Equal(t, GetSnykUI(engine.GetConfiguration()), engine.GetConfiguration().Get(configuration.WEB_APP_URL))
	})

	t.Run("Empty Api Endpoint should fall back to default and return default SnykUI Url", func(t *testing.T) {
		apiEndpoint := ""
		UpdateApiEndpointsOnConfig(engine.GetConfiguration(), apiEndpoint)
		uiEndpoint := GetSnykUI(engine.GetConfiguration())
		assert.Equal(t, "https://app.snyk.io", uiEndpoint)
	})

	t.Run("Fedramp API Endpoint provided with 'api' prefix", func(t *testing.T) {
		apiEndpoint := "https://api.fedramp.snykgov.io"
		UpdateApiEndpointsOnConfig(engine.GetConfiguration(), apiEndpoint)
		uiEndpoint := GetSnykUI(engine.GetConfiguration())
		assert.Equal(t, "https://app.fedramp.snykgov.io", uiEndpoint)
	})
}

func TestConfig_shouldUpdateOAuth2Token(t *testing.T) {
	// add test cases
	engine, _ := initEngineForConfigTest(t)

	token := oauth2.Token{
		AccessToken:  "aaa",
		RefreshToken: "bbb",
		Expiry:       time.Now().Add(time.Hour),
	}

	newTokenBytes, err := json.Marshal(token)
	require.NoError(t, err)

	logger := engine.GetLogger()

	t.Run("old token empty -> true", func(t *testing.T) {
		assert.True(t, shouldUpdateToken("", string(newTokenBytes), logger))
	})
	t.Run("new token empty -> true", func(t *testing.T) {
		assert.True(t, shouldUpdateToken(string(newTokenBytes), "", logger))
	})
	t.Run("both tokens empty -> false", func(t *testing.T) {
		assert.True(t, shouldUpdateToken("", "", logger))
	})
	t.Run("old token expires after new token -> false", func(t *testing.T) {
		oldToken := token
		oldToken.Expiry = token.Expiry.Add(time.Hour)
		oldTokenBytes, err := json.Marshal(oldToken)
		require.NoError(t, err)

		assert.False(t, shouldUpdateToken(string(oldTokenBytes), string(newTokenBytes), logger))
	})
	t.Run("old token expires before new token -> true", func(t *testing.T) {
		oldToken := token
		oldToken.Expiry = token.Expiry.Add(-time.Hour)
		oldTokenBytes, err := json.Marshal(oldToken)
		require.NoError(t, err)

		assert.True(t, shouldUpdateToken(string(oldTokenBytes), string(newTokenBytes), logger))
	})
	t.Run("old token not an oauth token, but new one is -> true", func(t *testing.T) {
		assert.True(t, shouldUpdateToken(uuid.NewString(), string(newTokenBytes), logger))
	})
	t.Run("new token not an oauth token -> false", func(t *testing.T) {
		assert.False(t, shouldUpdateToken(string(newTokenBytes), uuid.NewString(), logger))
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
	engine, ts := initEngineForConfigTest(t)
	assert.False(t, AuthenticationMethodMatchesCredentials(GetToken(engine.GetConfiguration()), GetAuthenticationMethodFromConfig(engine.GetConfiguration()), engine.GetLogger()))

	for _, method := range append(slices.Collect(maps.Keys(tokenMap)), types.FakeAuthentication) {
		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(method))
		for tokenType, token := range tokenMap {
			ts.SetToken(engine.GetConfiguration(), token)
			// Fake authentication should allow any token type, otherwise the authentication method must match.
			shouldMatch := method == tokenType || method == types.FakeAuthentication
			t.Run(fmt.Sprintf("method: %s, token type: %s -> %t", method, tokenType, shouldMatch), func(t *testing.T) {
				if shouldMatch {
					assert.True(t, AuthenticationMethodMatchesCredentials(GetToken(engine.GetConfiguration()), GetAuthenticationMethodFromConfig(engine.GetConfiguration()), engine.GetLogger()))
				} else {
					assert.False(t, AuthenticationMethodMatchesCredentials(GetToken(engine.GetConfiguration()), GetAuthenticationMethodFromConfig(engine.GetConfiguration()), engine.GetLogger()))
				}
			})
		}
	}
}

func TestLdxSyncMachineScopeConfigFields(t *testing.T) {
	t.Run("CodeEndpoint getter/setter", func(t *testing.T) {
		engine, _ := initEngineForConfigTest(t)
		conf := engine.GetConfiguration()
		assert.Equal(t, "", conf.GetString(configresolver.UserGlobalKey(types.SettingCodeEndpoint)))
		conf.Set(configresolver.UserGlobalKey(types.SettingCodeEndpoint), "https://deeproxy.custom.snyk.io")
		assert.Equal(t, "https://deeproxy.custom.snyk.io", conf.GetString(configresolver.UserGlobalKey(types.SettingCodeEndpoint)))
	})

	t.Run("ProxyHttp getter/setter", func(t *testing.T) {
		engine, _ := initEngineForConfigTest(t)
		conf := engine.GetConfiguration()
		assert.Equal(t, "", conf.GetString(configresolver.UserGlobalKey(types.SettingProxyHttp)))
		conf.Set(configresolver.UserGlobalKey(types.SettingProxyHttp), "http://proxy:8080")
		assert.Equal(t, "http://proxy:8080", conf.GetString(configresolver.UserGlobalKey(types.SettingProxyHttp)))
	})

	t.Run("ProxyHttps getter/setter", func(t *testing.T) {
		engine, _ := initEngineForConfigTest(t)
		conf := engine.GetConfiguration()
		assert.Equal(t, "", conf.GetString(configresolver.UserGlobalKey(types.SettingProxyHttps)))
		conf.Set(configresolver.UserGlobalKey(types.SettingProxyHttps), "https://proxy:8443")
		assert.Equal(t, "https://proxy:8443", conf.GetString(configresolver.UserGlobalKey(types.SettingProxyHttps)))
	})

	t.Run("ProxyNoProxy getter/setter", func(t *testing.T) {
		engine, _ := initEngineForConfigTest(t)
		conf := engine.GetConfiguration()
		assert.Equal(t, "", conf.GetString(configresolver.UserGlobalKey(types.SettingProxyNoProxy)))
		conf.Set(configresolver.UserGlobalKey(types.SettingProxyNoProxy), "localhost,127.0.0.1")
		assert.Equal(t, "localhost,127.0.0.1", conf.GetString(configresolver.UserGlobalKey(types.SettingProxyNoProxy)))
	})

	t.Run("IsProxyInsecure getter/setter", func(t *testing.T) {
		engine, _ := initEngineForConfigTest(t)
		conf := engine.GetConfiguration()
		key := configresolver.UserGlobalKey(types.SettingProxyInsecure)
		assert.False(t, conf.GetBool(key))
		conf.Set(key, true)
		assert.True(t, conf.GetBool(key))
	})

	t.Run("IsPublishSecurityAtInceptionRulesEnabled getter/setter", func(t *testing.T) {
		engine, _ := initEngineForConfigTest(t)
		conf := engine.GetConfiguration()
		key := configresolver.UserGlobalKey(types.SettingPublishSecurityAtInceptionRules)
		assert.False(t, conf.GetBool(key))
		conf.Set(key, true)
		assert.True(t, conf.GetBool(key))
	})

	t.Run("CliReleaseChannel getter/setter", func(t *testing.T) {
		engine, _ := initEngineForConfigTest(t)
		conf := engine.GetConfiguration()
		assert.Equal(t, "", conf.GetString(configresolver.UserGlobalKey(types.SettingCliReleaseChannel)))
		conf.Set(configresolver.UserGlobalKey(types.SettingCliReleaseChannel), "stable")
		assert.Equal(t, "stable", conf.GetString(configresolver.UserGlobalKey(types.SettingCliReleaseChannel)))
	})
}
func Test_SetOrganization_SkipsRedundantSets(t *testing.T) {
	t.Run("Redundant UUID set is skipped", func(t *testing.T) {
		setCallCount := 0
		mockConfig := setupMockOrgSetAndGet(t, &setCallCount, nil, "00000000-0000-0000-0000-999999999999")

		orgUUID := "00000000-0000-0000-0000-000000000001"

		// First set calls configuration Set(ORGANIZATION)
		SetOrganization(mockConfig, orgUUID)
		assert.Equal(t, 1, setCallCount, "First SetOrganization calls Set once")
		actualOrg := mockConfig.GetString(configuration.ORGANIZATION)
		assert.Equal(t, orgUUID, actualOrg)

		// Redundant set - should skip configuration Set entirely
		SetOrganization(mockConfig, orgUUID)
		assert.Equal(t, 1, setCallCount, "Redundant SetOrganization skips Set, still 1")

		// Verify value is still correct (Get doesn't increment Set count)
		actualOrg = mockConfig.GetString(configuration.ORGANIZATION)
		assert.Equal(t, orgUUID, actualOrg)
		assert.Equal(t, 1, setCallCount, "Organization() Get doesn't call Set, still 1")
	})

	t.Run("Different UUID value triggers new set", func(t *testing.T) {
		setCallCount := 0
		mockConfig := setupMockOrgSetAndGet(t, &setCallCount, nil, "00000000-0000-0000-0000-999999999999")

		orgUUID1 := "00000000-0000-0000-0000-000000000011"
		orgUUID2 := "00000000-0000-0000-0000-000000000022"

		// Set first value
		SetOrganization(mockConfig, orgUUID1)
		assert.Equal(t, 1, setCallCount, "First SetOrganization calls Set once")
		assert.Equal(t, orgUUID1, mockConfig.GetString(configuration.ORGANIZATION))

		// Set different value - should call Set again
		SetOrganization(mockConfig, orgUUID2)
		assert.Equal(t, 2, setCallCount, "Different SetOrganization calls Set again = 2 total")
		assert.Equal(t, orgUUID2, mockConfig.GetString(configuration.ORGANIZATION))
	})

	t.Run("Whitespace is trimmed and redundant set is skipped", func(t *testing.T) {
		setCallCount := 0
		mockConfig := setupMockOrgSetAndGet(t, &setCallCount, nil, "00000000-0000-0000-0000-999999999999")

		orgUUID := "00000000-0000-0000-0000-000000000033"

		// Set with whitespace - trimmed internally
		SetOrganization(mockConfig, "  "+orgUUID+"  ")
		assert.Equal(t, 1, setCallCount, "SetOrganization calls Set once")
		assert.Equal(t, orgUUID, mockConfig.GetString(configuration.ORGANIZATION))

		// Same value without whitespace should be skipped (trimmed value matches)
		SetOrganization(mockConfig, orgUUID)
		assert.Equal(t, 1, setCallCount, "Redundant SetOrganization skipped, still 1")
	})
}

func Test_SetOrganization_SkipsRedundantBlankSets(t *testing.T) {
	t.Run("Multiple blank sets are all skipped", func(t *testing.T) {
		setCallCount := 0
		preferredOrgUUID := "00000000-0000-0000-0000-000000000001"
		mockConfig := setupMockOrgSetAndGet(t, &setCallCount, nil, preferredOrgUUID)

		// Initial state is blank, setting to blank is redundant
		SetOrganization(mockConfig, "")
		assert.Equal(t, 0, setCallCount, "First blank Set skipped - already blank")

		actualOrg := mockConfig.GetString(configuration.ORGANIZATION)
		assert.Equal(t, preferredOrgUUID, actualOrg, "Get resolves blank to preferred UUID")

		// Another blank set after Get - still skipped
		SetOrganization(mockConfig, "")
		assert.Equal(t, 0, setCallCount, "Second blank Set skipped - still blank")

		// Verify Get still works
		actualOrg = mockConfig.GetString(configuration.ORGANIZATION)
		assert.Equal(t, preferredOrgUUID, actualOrg, "Get still resolves blank to preferred UUID")
	})

	t.Run("Blank after non-blank UUID goes through", func(t *testing.T) {
		setCallCount := 0
		preferredOrgUUID := "00000000-0000-0000-0000-000000000001"
		mockConfig := setupMockOrgSetAndGet(t, &setCallCount, nil, preferredOrgUUID)

		specificUUID := "00000000-0000-0000-0000-000000000002"
		SetOrganization(mockConfig, specificUUID)
		assert.Equal(t, 1, setCallCount, "First SetOrganization calls Set once")
		assert.Equal(t, specificUUID, mockConfig.GetString(configuration.ORGANIZATION))

		// Now set back to blank - different value so should call Set
		SetOrganization(mockConfig, "")
		assert.Equal(t, 2, setCallCount, "Different SetOrganization calls Set again = 2 total")
		assert.Equal(t, preferredOrgUUID, mockConfig.GetString(configuration.ORGANIZATION), "Get resolves blank to preferred UUID")
	})
}

func Test_SetOrganization_SkipsRedundantSlugSets(t *testing.T) {
	const (
		orgSlug1 = "my-org-slug"
		orgSlug2 = "different-org-slug"
	)

	slugToUUIDMap := map[string]string{
		orgSlug1: "00000000-0000-0000-0000-000000000001",
		orgSlug2: "00000000-0000-0000-0000-000000000002",
	}

	t.Run("Redundant slug set is skipped", func(t *testing.T) {
		setCallCount := 0
		mockConfig := setupMockOrgSetAndGet(t, &setCallCount, slugToUUIDMap, "00000000-0000-0000-0000-999999999999")

		// First set
		SetOrganization(mockConfig, orgSlug1)
		assert.Equal(t, 1, setCallCount, "First SetOrganization calls Set once")
		actualOrg := mockConfig.GetString(configuration.ORGANIZATION)
		assert.Equal(t, slugToUUIDMap[orgSlug1], actualOrg, "Get resolves slug to UUID")

		// Redundant slug set - should skip the configuration Set call
		SetOrganization(mockConfig, orgSlug1)
		assert.Equal(t, 1, setCallCount, "Redundant SetOrganization skipped, still 1")

		// Verify resolution still works on read
		actualOrg = mockConfig.GetString(configuration.ORGANIZATION)
		assert.Equal(t, slugToUUIDMap[orgSlug1], actualOrg, "Get still resolves slug to UUID")
	})

	t.Run("Different slug goes through", func(t *testing.T) {
		setCallCount := 0
		mockConfig := setupMockOrgSetAndGet(t, &setCallCount, slugToUUIDMap, "00000000-0000-0000-0000-999999999999")

		// First slug
		SetOrganization(mockConfig, orgSlug1)
		assert.Equal(t, 1, setCallCount, "First SetOrganization calls Set once")
		actualOrg := mockConfig.GetString(configuration.ORGANIZATION)
		assert.Equal(t, slugToUUIDMap[orgSlug1], actualOrg, "Get resolves first slug to UUID")

		// Different slug - should call Set again
		SetOrganization(mockConfig, orgSlug2)
		assert.Equal(t, 2, setCallCount, "Different SetOrganization calls Set again = 2 total")

		// Verify new slug resolves to different UUID
		actualOrg = mockConfig.GetString(configuration.ORGANIZATION)
		assert.Equal(t, slugToUUIDMap[orgSlug2], actualOrg, "Get resolves new slug to UUID")
	})
}

// setupMockOrgSetAndGet sets up a mock configuration that mocks Set(ORGANIZATION) and GetString(ORGANIZATION).
// Tracks Set calls via counter and handles Get with optional resolution logic for slugs and blank values.
func setupMockOrgSetAndGet(t *testing.T, setCallCounter *int, fakeSlugToUUIDResolutionMap map[string]string, fakeUserPreferredDefaultOrgFromWebUI string) *mocks.MockConfiguration {
	t.Helper()

	ctrl := gomock.NewController(t)
	mockConfig := mocks.NewMockConfiguration(ctrl)

	// Storage for current org value
	var currentSetOrg string

	// Spy on Set(ORGANIZATION, ...) and track calls
	mockConfig.EXPECT().
		Set(configuration.ORGANIZATION, gomock.Any()).
		Do(func(key string, value any) {
			*setCallCounter++
			currentSetOrg = value.(string)
		}).
		AnyTimes()

	// Mock GetString(ORGANIZATION) with optional resolution logic
	mockConfig.EXPECT().
		GetString(configuration.ORGANIZATION).
		DoAndReturn(func(key string) string {
			// Handle blank resolution
			if currentSetOrg == "" {
				return fakeUserPreferredDefaultOrgFromWebUI
			}

			// Handle slug->UUID resolution
			if fakeSlugToUUIDResolutionMap != nil {
				if uuid, found := fakeSlugToUUIDResolutionMap[currentSetOrg]; found {
					return uuid
				}
			}

			// Return value as-is (UUIDs don't need resolution)
			return currentSetOrg
		}).
		AnyTimes()

	// Track last_set_organization in GAF
	var lastSetOrg string
	lastSetOrgKey := configresolver.UserGlobalKey(types.SettingLastSetOrganization)
	mockConfig.EXPECT().
		GetString(lastSetOrgKey).
		DoAndReturn(func(key string) string { return lastSetOrg }).
		AnyTimes()
	mockConfig.EXPECT().
		Set(lastSetOrgKey, gomock.Any()).
		Do(func(key string, value any) { lastSetOrg = value.(string) }).
		AnyTimes()

	// SetOrganization also sets UserGlobalKey(SettingOrganization) for /rest/self-free reads.
	mockConfig.EXPECT().
		Set(configresolver.UserGlobalKey(types.SettingOrganization), gomock.Any()).
		AnyTimes()

	return mockConfig
}

func Test_IsAnalyticsPermittedForAPI(t *testing.T) {
	t.Run("allowed for api.snyk.io", func(t *testing.T) {
		assert.True(t, IsAnalyticsPermittedForAPI("https://api.snyk.io"))
	})
	t.Run("allowed for api.us.snyk.io", func(t *testing.T) {
		assert.True(t, IsAnalyticsPermittedForAPI("https://api.us.snyk.io"))
	})
	t.Run("not allowed for custom endpoint", func(t *testing.T) {
		assert.False(t, IsAnalyticsPermittedForAPI("https://api.custom.snyk.io"))
	})
	t.Run("not allowed for empty string", func(t *testing.T) {
		assert.False(t, IsAnalyticsPermittedForAPI(""))
	})
	t.Run("not allowed for invalid URL", func(t *testing.T) {
		assert.False(t, IsAnalyticsPermittedForAPI("://invalid"))
	})
}

func Test_UpdateApiEndpointsOnConfig(t *testing.T) {
	engine, _ := initEngineForConfigTest(t)
	conf := engine.GetConfiguration()

	t.Run("sets API endpoints and returns true on change", func(t *testing.T) {
		changed := UpdateApiEndpointsOnConfig(conf, "https://api.custom.snyk.io")
		assert.True(t, changed)
		assert.Equal(t, "https://api.custom.snyk.io", conf.GetString(configresolver.UserGlobalKey(types.SettingApiEndpoint)))
		assert.Equal(t, "https://api.custom.snyk.io", conf.GetString(configuration.API_URL))
	})

	t.Run("returns false when setting same value", func(t *testing.T) {
		changed := UpdateApiEndpointsOnConfig(conf, "https://api.custom.snyk.io")
		assert.False(t, changed)
	})

	t.Run("defaults to DefaultSnykApiUrl when empty", func(t *testing.T) {
		conf.Set(configresolver.UserGlobalKey(types.SettingApiEndpoint), "something-else")
		changed := UpdateApiEndpointsOnConfig(conf, "")
		assert.True(t, changed)
		assert.Equal(t, DefaultSnykApiUrl, conf.GetString(configresolver.UserGlobalKey(types.SettingApiEndpoint)))
	})
}

func Test_FolderOrganizationFromConfig(t *testing.T) {
	engine, _ := initEngineForConfigTest(t)
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()
	folderPath := types.FilePath(t.TempDir())

	t.Run("returns global org when no folder-specific org", func(t *testing.T) {
		globalOrgUUID := "00000000-0000-0000-0000-000000000099"
		conf.Set(configuration.ORGANIZATION, globalOrgUUID)
		org := FolderOrganizationFromConfig(conf, folderPath, logger)
		assert.Equal(t, globalOrgUUID, org)
	})

	t.Run("returns preferred org when set by user", func(t *testing.T) {
		types.SetPreferredOrgAndOrgSetByUser(conf, folderPath, "user-org", true)
		org := FolderOrganizationFromConfig(conf, folderPath, logger)
		assert.Equal(t, "user-org", org)
	})

	t.Run("returns auto-determined org when not set by user", func(t *testing.T) {
		types.SetPreferredOrgAndOrgSetByUser(conf, folderPath, "", false)
		types.SetFolderMetadataSetting(conf, folderPath, types.SettingAutoDeterminedOrg, "auto-org")
		org := FolderOrganizationFromConfig(conf, folderPath, logger)
		assert.Equal(t, "auto-org", org)
	})
}

func Test_GetFolderConfigFromEngine(t *testing.T) {
	engine, _ := initEngineForConfigTest(t)

	t.Run("returns folder config with engine and resolver wired", func(t *testing.T) {
		folderPath := types.FilePath(t.TempDir())
		fc := GetFolderConfigFromEngine(engine, defaultConfigResolverForTest(engine), folderPath, engine.GetLogger())
		require.NotNil(t, fc)
		assert.Equal(t, folderPath, fc.FolderPath)
		assert.NotNil(t, fc.Engine)
		assert.NotNil(t, fc.Conf())
	})

	t.Run("returns minimal config on storage error for nonexistent path", func(t *testing.T) {
		nonexistentPath := types.FilePath(filepath.Join(string(filepath.Separator), "nonexistent", "path", "that", "does", "not", "exist"))
		fc := GetFolderConfigFromEngine(engine, defaultConfigResolverForTest(engine), nonexistentPath, engine.GetLogger())
		require.NotNil(t, fc)
		assert.Equal(t, types.PathKey(nonexistentPath), fc.FolderPath)
		assert.NotNil(t, fc.Engine)
	})
}

func Test_GetImmutableFolderConfigFromEngine(t *testing.T) {
	engine, _ := initEngineForConfigTest(t)

	t.Run("returns immutable folder config with engine wired", func(t *testing.T) {
		folderPath := types.FilePath(t.TempDir())
		fc := GetUnenrichedFolderConfigFromEngine(engine, defaultConfigResolverForTest(engine), folderPath, engine.GetLogger())
		require.NotNil(t, fc)
		assert.Equal(t, folderPath, fc.FolderPath)
		assert.NotNil(t, fc.Engine)
		assert.NotNil(t, fc.Conf())
	})
}

func Test_ParseOAuthToken(t *testing.T) {
	logger := zerolog.Nop()

	t.Run("parses valid OAuth2 JSON token", func(t *testing.T) {
		validToken := `{"access_token":"at","token_type":"bearer","refresh_token":"rt","expiry":"2030-01-01T00:00:00Z"}`
		token, err := ParseOAuthToken(validToken, &logger)
		require.NoError(t, err)
		assert.Equal(t, "at", token.AccessToken)
		assert.Equal(t, "bearer", token.TokenType)
		assert.Equal(t, "rt", token.RefreshToken)
	})

	t.Run("returns error for legacy UUID token", func(t *testing.T) {
		legacyToken := "00000000-0000-0000-0000-000000000001"
		_, err := ParseOAuthToken(legacyToken, &logger)
		assert.Error(t, err)
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		_, err := ParseOAuthToken("not-json-not-uuid", &logger)
		assert.Error(t, err)
	})

	t.Run("returns error for empty string", func(t *testing.T) {
		_, err := ParseOAuthToken("", &logger)
		assert.Error(t, err)
	})
}
