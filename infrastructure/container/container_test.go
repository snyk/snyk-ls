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

package container

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

// MockRoundTripper is a mock HTTP transport for testing
type MockRoundTripper struct {
	Response *http.Response
	Error    error
}

func (m *MockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.Error != nil {
		return nil, m.Error
	}
	return m.Response, nil
}

// mockHttpClientWithResponse returns a mock HTTP client that returns the given response
func mockHttpClientWithResponse(statusCode int, body string) func() *http.Client {
	return func() *http.Client {
		return &http.Client{
			Transport: &MockRoundTripper{
				Response: &http.Response{
					StatusCode: statusCode,
					Body:       io.NopCloser(bytes.NewBufferString(body)),
					Header:     make(http.Header),
				},
			},
		}
	}
}

// mockHttpClient returns a mock HTTP client with default successful response
func mockHttpClient() func() *http.Client {
	mockResponse := `{
		"baseImage": "ubuntu:18.04",
		"recommendations": [
			{
				"image": "ubuntu:22.04-slim",
				"reason": "Latest LTS version with security patches"
			}
		],
		"minorUpgrades": [
			{
				"image": "ubuntu:18.04.6",
				"reason": "Minor version upgrade with security fixes"
			}
		],
		"majorUpgrades": [
			{
				"image": "ubuntu:22.04",
				"reason": "Major version upgrade"
			}
		],
		"alternativeImages": []
	}`
	return mockHttpClientWithResponse(200, mockResponse)
}

func TestScanner_Product(t *testing.T) {
	c := config.New()
	scanner := New(c, error_reporting.NewTestErrorReporter(), mockHttpClient())

	assert.Equal(t, product.ProductContainer, scanner.Product())
}

func TestScanner_IsEnabled(t *testing.T) {
	c := config.New()
	scanner := New(c, error_reporting.NewTestErrorReporter(), mockHttpClient())

	// Test when container is disabled (default)
	assert.False(t, scanner.IsEnabled())

	// Test when container is enabled
	c.SetSnykContainerEnabled(true)
	assert.True(t, scanner.IsEnabled())
}

func TestScanner_Scan_Dockerfile(t *testing.T) {
	c := config.New()
	c.SetSnykContainerEnabled(true)
	scanner := New(c, error_reporting.NewTestErrorReporter(), mockHttpClient())

	// Create a temporary Dockerfile
	tmpDir := t.TempDir()
	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	dockerfileContent := `FROM ubuntu:18.04
RUN apt-get update
COPY . /app
WORKDIR /app
CMD ["./app"]`

	err := os.WriteFile(dockerfilePath, []byte(dockerfileContent), 0644)
	require.NoError(t, err)

	// Scan the Dockerfile
	ctx := t.Context()
	issues, err := scanner.Scan(ctx, types.FilePath(dockerfilePath), types.FilePath(tmpDir), nil)

	require.NoError(t, err)
	assert.Len(t, issues, 1)

	issue := issues[0]
	assert.Equal(t, "SNYK-CONTAINER-BASE-IMAGE-ubuntu:18.04", issue.GetID())
	assert.Equal(t, types.Medium, issue.GetSeverity())
	assert.Equal(t, types.ContainerIssue, issue.GetIssueType())
	assert.Equal(t, product.ProductContainer, issue.GetProduct())
	assert.Contains(t, issue.GetMessage(), "ubuntu:18.04")
	assert.Contains(t, issue.GetFormattedMessage(), "Container Base Image Recommendation")

	// Check code actions - should recommend the minor upgrade
	codeActions := issue.GetCodeActions()
	assert.Len(t, codeActions, 1)
	assert.Contains(t, codeActions[0].GetTitle(), "Upgrade to ubuntu:18.04.6")
}

func TestScanner_Scan_NonDockerFile(t *testing.T) {
	c := config.New()
	c.SetSnykContainerEnabled(true)
	scanner := New(c, error_reporting.NewTestErrorReporter(), mockHttpClient())

	// Create a temporary non-Docker file
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.txt")
	fileContent := `This is not a Dockerfile`

	err := os.WriteFile(filePath, []byte(fileContent), 0644)
	require.NoError(t, err)

	// Scan the file
	ctx := t.Context()
	issues, err := scanner.Scan(ctx, types.FilePath(filePath), types.FilePath(tmpDir), nil)

	require.NoError(t, err)
	assert.Len(t, issues, 0)
}

func TestScanner_Scan_Directory(t *testing.T) {
	c := config.New()
	c.SetSnykContainerEnabled(true)
	scanner := New(c, error_reporting.NewTestErrorReporter(), mockHttpClient())

	// Create a temporary directory
	tmpDir := t.TempDir()

	// Scan the directory
	ctx := t.Context()
	issues, err := scanner.Scan(ctx, types.FilePath(tmpDir), types.FilePath(tmpDir), nil)

	require.NoError(t, err)
	assert.Len(t, issues, 0)
}

func TestScanner_isDockerFile(t *testing.T) {
	c := config.New()
	scanner := New(c, error_reporting.NewTestErrorReporter(), mockHttpClient())

	testCases := []struct {
		fileName string
		expected bool
	}{
		{"dockerfile", true},
		{"Dockerfile", true},
		{"DOCKERFILE", true},
		{"dockerfile.dev", true},
		{"Dockerfile.prod", true},
		{"docker-compose.yml", true},
		{"docker-compose.yaml", true},
		{"test.txt", false},
		{"package.json", false},
		{"docker-compose.json", false},
	}

	for _, tc := range testCases {
		t.Run(tc.fileName, func(t *testing.T) {
			result := scanner.isDockerFile(tc.fileName)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestScanner_Scan_DockerCompose(t *testing.T) {
	c := config.New()
	c.SetSnykContainerEnabled(true)
	scanner := New(c, error_reporting.NewTestErrorReporter(), mockHttpClient())

	// Create a temporary docker-compose.yml
	tmpDir := t.TempDir()
	composePath := filepath.Join(tmpDir, "docker-compose.yml")
	composeContent := `version: '3'
services:
  web:
    image: nginx:1.19
    ports:
      - "80:80"
  db:
    image: postgres:12
    environment:
      POSTGRES_PASSWORD: password`

	err := os.WriteFile(composePath, []byte(composeContent), 0644)
	require.NoError(t, err)

	// Scan the docker-compose file
	ctx := t.Context()
	issues, err := scanner.Scan(ctx, types.FilePath(composePath), types.FilePath(tmpDir), nil)

	require.NoError(t, err)
	// Should not find issues in docker-compose files as they don't use FROM instructions
	assert.Len(t, issues, 0)
}

func TestScanner_Scan_MultipleFromInstructions(t *testing.T) {
	c := config.New()
	c.SetSnykContainerEnabled(true)
	scanner := New(c, error_reporting.NewTestErrorReporter(), mockHttpClient())

	// Create a Dockerfile with multiple FROM instructions (multi-stage build)
	tmpDir := t.TempDir()
	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	dockerfileContent := `FROM node:14 as builder
WORKDIR /app
COPY package*.json ./
RUN npm install

FROM nginx:1.19
COPY --from=builder /app/dist /usr/share/nginx/html`

	err := os.WriteFile(dockerfilePath, []byte(dockerfileContent), 0644)
	require.NoError(t, err)

	// Scan the Dockerfile
	ctx := t.Context()
	issues, err := scanner.Scan(ctx, types.FilePath(dockerfilePath), types.FilePath(tmpDir), nil)

	require.NoError(t, err)
	assert.Len(t, issues, 2) // Should find issues for both base images

	// Check that we have issues for both images
	imageNames := make(map[string]bool)
	for _, issue := range issues {
		if issue.GetID() == "SNYK-CONTAINER-BASE-IMAGE-node:14" {
			imageNames["node:14"] = true
		}
		if issue.GetID() == "SNYK-CONTAINER-BASE-IMAGE-nginx:1.19" {
			imageNames["nginx:1.19"] = true
		}
	}
	assert.True(t, imageNames["node:14"])
	assert.True(t, imageNames["nginx:1.19"])
}

func TestDockerDepsRemediationAPI_GetBaseImageRecommendation(t *testing.T) {
	c := config.New()
	mockResponse := `{
		"baseImage": "node:14",
		"recommendations": [
			{
				"image": "node:20-slim",
				"reason": "Latest LTS version with security patches"
			}
		],
		"minorUpgrades": [
			{
				"image": "node:14.21.3",
				"reason": "Minor version upgrade with security fixes"
			}
		],
		"majorUpgrades": [
			{
				"image": "node:20",
				"reason": "Major version upgrade"
			}
		],
		"alternativeImages": []
	}`

	api := &DockerDepsRemediationAPI{
		httpClient: mockHttpClientWithResponse(200, mockResponse),
		config:     c,
	}
	ctx := t.Context()

	recommendation, err := api.GetBaseImageRecommendation(ctx, "node:14")

	require.NoError(t, err)
	assert.Equal(t, "node:14", recommendation.OriginalImage)
	assert.Equal(t, "node:14.21.3", recommendation.RecommendedImage) // Should prefer minor upgrade
	assert.Equal(t, "Minor version upgrade with security fixes", recommendation.Reason)
	assert.NotEmpty(t, recommendation.SeverityReduction)
}

func TestDockerDepsRemediationAPI_GetBaseImageRecommendation_NoMinorUpgrades(t *testing.T) {
	c := config.New()
	mockResponse := `{
		"baseImage": "alpine:3.15",
		"recommendations": [
			{
				"image": "alpine:3.18-slim",
				"reason": "Latest stable version"
			}
		],
		"minorUpgrades": [],
		"majorUpgrades": [
			{
				"image": "alpine:3.18",
				"reason": "Major version upgrade"
			}
		],
		"alternativeImages": []
	}`

	api := &DockerDepsRemediationAPI{
		httpClient: mockHttpClientWithResponse(200, mockResponse),
		config:     c,
	}
	ctx := t.Context()

	_, err := api.GetBaseImageRecommendation(ctx, "alpine:3.15")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no minor version recommendations available for base image: alpine:3.15")
}

func TestDockerDepsRemediationAPI_GetBaseImageRecommendation_APIError(t *testing.T) {
	c := config.New()

	api := &DockerDepsRemediationAPI{
		httpClient: mockHttpClientWithResponse(404, "Not Found"),
		config:     c,
	}
	ctx := t.Context()

	_, err := api.GetBaseImageRecommendation(ctx, "unknown:latest")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "API request failed with status 404")
}

func TestDockerDepsRemediationAPI_GetBaseImageRecommendation_NoRecommendations(t *testing.T) {
	c := config.New()
	mockResponse := `{
		"baseImage": "scratch",
		"recommendations": [],
		"minorUpgrades": [],
		"majorUpgrades": [],
		"alternativeImages": []
	}`

	api := &DockerDepsRemediationAPI{
		httpClient: mockHttpClientWithResponse(200, mockResponse),
		config:     c,
	}
	ctx := t.Context()

	_, err := api.GetBaseImageRecommendation(ctx, "scratch")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no minor version recommendations available for base image: scratch")
}
