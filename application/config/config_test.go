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
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"

	"github.com/snyk/snyk-ls/infrastructure/cli/cli_constants"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/internal/lsp"
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
		config.authenticationMethod = lsp.OAuthAuthentication
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

	assert.True(t, c.IsTelemetryEnabled(), "Telemetry should be enabled by default")
	assert.True(t, c.IsErrorReportingEnabled(), "Error Reporting should be enabled by default")
	assert.False(t, c.IsSnykAdvisorEnabled(), "Advisor should be disabled by default")
	assert.False(t, c.IsSnykCodeEnabled(), "Snyk Code should be disabled by default")
	assert.False(t, c.IsSnykContainerEnabled(), "Snyk Container should be disabled by default")
	assert.False(t, c.IsDeltaFindingsEnabled(), "Delta Findings should be disabled by default")
	assert.True(t, c.IsSnykOssEnabled(), "Snyk Open Source should be enabled by default")
	assert.True(t, c.IsSnykIacEnabled(), "Snyk IaC should be enabled by default")
	assert.Equal(t, "", c.LogPath(), "Logpath should be empty by default")
	assert.Equal(t, "md", c.Format(), "Output format should be md by default")
	assert.Equal(t, lsp.DefaultSeverityFilter(), c.FilterSeverity(), "All severities should be enabled by default")
	assert.Empty(t, c.trustedFolders)
	assert.Equal(t, lsp.TokenAuthentication, c.authenticationMethod)
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

func Test_updatePath(t *testing.T) {
	t.Setenv("PATH", "a")
	c := New()

	c.updatePath("b")

	assert.Contains(t, c.path, string(os.PathListSeparator)+"b")
	assert.Contains(t, c.path, "a"+string(os.PathListSeparator))
}

func Test_loadFile(t *testing.T) {
	t.Setenv("A", "")
	t.Setenv("C", "")
	_ = os.Unsetenv("A")
	_ = os.Unsetenv("C")
	envData := []byte("A=B\nC=D")
	file, err := os.CreateTemp(".", "config_test_loadFile")
	if err != nil {
		assert.Fail(t, "Couldn't create temp file", err)
	}
	defer func(file *os.File) {
		_ = file.Close()
		_ = os.Remove(file.Name())
	}(file)
	if err != nil {
		assert.Fail(t, "Couldn't create test file")
	}
	_, _ = file.Write(envData)
	if err != nil {
		assert.Fail(t, "Couldn't write to test file")
	}

	CurrentConfig().loadFile(file.Name())

	assert.Equal(t, "B", os.Getenv("A"))
	assert.Equal(t, "D", os.Getenv("C"))
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
		c.SetSeverityFilter(lsp.NewSeverityFilter(true, true, false, false))
		assert.Equal(t, lsp.NewSeverityFilter(true, true, false, false), c.FilterSeverity())
	})

	t.Run("Returns correctly", func(t *testing.T) {
		c := New()
		lowExcludedFilter := lsp.NewSeverityFilter(true, true, false, false)

		modified := c.SetSeverityFilter(lowExcludedFilter)
		assert.True(t, modified)

		modified = c.SetSeverityFilter(lowExcludedFilter)
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

func Test_IsTelemetryEnabled(t *testing.T) {
	t.Setenv(EnableTelemetry, "1")
	c := New()

	// case: disabled via env var
	assert.False(t, c.IsTelemetryEnabled())
	assert.True(t, c.Engine().GetConfiguration().GetBool(configuration.ANALYTICS_DISABLED))

	// case: enabled via setter
	c.SetTelemetryEnabled(true)
	assert.True(t, c.IsTelemetryEnabled())
	assert.False(t, c.Engine().GetConfiguration().GetBool(configuration.ANALYTICS_DISABLED))

	// case: disabled via setter
	c.SetTelemetryEnabled(false)
	assert.False(t, c.IsTelemetryEnabled())
	assert.True(t, c.Engine().GetConfiguration().GetBool(configuration.ANALYTICS_DISABLED))
}

func TestSnykUiEndpoint(t *testing.T) {
	c := New()
	t.Run("Default Api Endpoint with /api prefix", func(t *testing.T) {
		uiEndpoint := c.SnykUi()
		assert.Equal(t, "https://app.snyk.io", uiEndpoint)
	})

	t.Run("API endpoint provided without 'app' prefix", func(t *testing.T) {
		apiEndpoint := "https://snyk.io/api/v1"
		c.UpdateApiEndpoints(apiEndpoint)
		uiEndpoint := c.SnykUi()
		assert.Equal(t, "https://app.snyk.io", uiEndpoint)
	})

	t.Run("API endpoint provided with 'app' prefix with v1 suffix", func(t *testing.T) {
		apiEndpoint := "https://app.snyk.io/api/v1"
		c.UpdateApiEndpoints(apiEndpoint)
		uiEndpoint := c.SnykUi()
		assert.Equal(t, "https://app.snyk.io", uiEndpoint)
	})

	t.Run("endpoint provided with 'app' prefix without v1 suffix", func(t *testing.T) {
		apiEndpoint := "https://app.snyk.io/api"
		c.UpdateApiEndpoints(apiEndpoint)
		uiEndpoint := c.SnykUi()
		assert.Equal(t, "https://app.snyk.io", uiEndpoint)
	})

	t.Run("Api endpoint provided with 'api' prefix", func(t *testing.T) {
		apiEndpoint := "https://api.snyk.io"
		c.UpdateApiEndpoints(apiEndpoint)
		uiEndpoint := c.SnykUi()
		assert.Equal(t, "https://app.snyk.io", uiEndpoint)
	})

	t.Run("Api endpoint provided with 'api' and 'eu' prefix", func(t *testing.T) {
		apiEndpoint := "https://api.eu.snyk.io"
		c.UpdateApiEndpoints(apiEndpoint)
		uiEndpoint := c.SnykUi()
		assert.Equal(t, "https://app.eu.snyk.io", uiEndpoint)
	})

	t.Run("Empty Api Endpoint should fall back to default and return default SnykUi Url", func(t *testing.T) {
		apiEndpoint := ""
		c.UpdateApiEndpoints(apiEndpoint)
		uiEndpoint := c.SnykUi()
		assert.Equal(t, "https://app.snyk.io", uiEndpoint)
	})

	t.Run("Fedramp API Endpoint provided with 'api' prefix", func(t *testing.T) {
		apiEndpoint := "https://api.fedramp.snykgov.io"
		c.UpdateApiEndpoints(apiEndpoint)
		uiEndpoint := c.SnykUi()
		assert.Equal(t, "https://app.fedramp.snykgov.io", uiEndpoint)
	})
}
