/*
 * Copyright 2022 Snyk Ltd.
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
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestSetToken(t *testing.T) {
	SetCurrentConfig(New())
	oldToken := CurrentConfig().Token()
	CurrentConfig().SetToken("asdf")
	assert.Equal(t, CurrentConfig().Token(), "asdf")
	CurrentConfig().SetToken(oldToken)
}

func TestConfigDefaults(t *testing.T) {
	c := New()

	assert.True(t, c.IsTelemetryEnabled(), "Telemetry should be enabled by default")
	assert.True(t, c.IsErrorReportingEnabled(), "Error Reporting should be enabled by default")
	assert.False(t, c.IsSnykAdvisorEnabled(), "Advisor should be disabled by default")
	assert.False(t, c.IsSnykCodeEnabled(), "Snyk Code should be disabled by default")
	assert.False(t, c.IsSnykContainerEnabled(), "Snyk Container should be enabled by default")
	assert.True(t, c.IsSnykOssEnabled(), "Snyk Open Source should be enabled by default")
	assert.True(t, c.IsSnykIacEnabled(), "Snyk IaC should be enabled by default")
	assert.Equal(t, "", c.LogPath(), "Logpath should be empty by default")
	assert.Equal(t, "md", c.Format(), "Output format should be md by default")
	assert.Empty(t, c.trustedFolders)
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
	<-tokenChangedChannel
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
	assert.Equal(t, duration, snykCodeAnalysisTimeoutFromEnv())
}

func Test_SnykCodeAnalysisTimeoutReturnsDefaultIfNoEnvVariableFound(t *testing.T) {
	t.Setenv(snykCodeTimeoutKey, "")
	duration, _ := time.ParseDuration("10m")
	assert.Equal(t, duration, snykCodeAnalysisTimeoutFromEnv())
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
	os.Unsetenv("A")
	os.Unsetenv("C")
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
