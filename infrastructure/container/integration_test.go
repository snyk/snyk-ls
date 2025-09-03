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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// TestBaseImageDetection verifies that the scanner can properly parse and detect base images
func TestBaseImageDetection(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetSnykContainerEnabled(true)

	// Create a mock API that returns a realistic recommendation
	mockAPI := &MockBaseImageRemediationAPI{
		response: &BaseImageRecommendation{
			OriginalImage:     "ubuntu:18.04",
			RecommendedImage:  "ubuntu:22.04",
			Reason:            "Newer LTS version with security patches and fewer vulnerabilities",
			SeverityReduction: "Upgrading reduces 150+ known vulnerabilities",
		},
		err: nil,
	}
	scanner := newMockScanner(c, mockAPI)

	// Create a test Dockerfile with various FROM instructions
	tmpDir := t.TempDir()
	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	dockerfileContent := `# Multi-stage build example
FROM ubuntu:18.04 as base
RUN apt-get update && apt-get install -y curl

FROM node:14 as builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

FROM nginx:1.19-alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY --from=base /usr/bin/curl /usr/bin/curl
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]`

	err := os.WriteFile(dockerfilePath, []byte(dockerfileContent), 0644)
	require.NoError(t, err)

	// Scan the Dockerfile
	ctx := t.Context()
	issues, err := scanner.Scan(ctx, types.FilePath(dockerfilePath), types.FilePath(tmpDir), nil)

	require.NoError(t, err)
	t.Logf("Found %d issues in multi-stage Dockerfile", len(issues))

	// Should detect all 3 base images (ubuntu:18.04, node:14, nginx:1.19-alpine)
	assert.GreaterOrEqual(t, len(issues), 3, "Should find at least 3 base image issues")

	// Verify issue properties
	baseImagesFound := make(map[string]bool)
	for _, issue := range issues {
		t.Logf("Issue: ID=%s, Severity=%s, Product=%v", issue.GetID(), issue.GetSeverity(), issue.GetProduct())

		assert.Equal(t, product.ProductContainer, issue.GetProduct())
		assert.Equal(t, types.ContainerIssue, issue.GetIssueType())
		assert.NotEmpty(t, issue.GetMessage())
		assert.NotEmpty(t, issue.GetFormattedMessage())
		assert.Contains(t, issue.GetFormattedMessage(), "Container Base Image Recommendation")

		// Verify code actions exist
		codeActions := issue.GetCodeActions()
		if len(codeActions) > 0 {
			assert.NotEmpty(t, codeActions[0].GetTitle())
			assert.Contains(t, codeActions[0].GetTitle(), "Upgrade to")
			t.Logf("Code action: %s", codeActions[0].GetTitle())
		}

		// Track which base images were found (IDs include line number)
		if issue.GetID() == "SNYK-CONTAINER-BASE-IMAGE-ubuntu:18.04-1" {
			baseImagesFound["ubuntu:18.04"] = true
		} else if issue.GetID() == "SNYK-CONTAINER-BASE-IMAGE-node:14-4" {
			baseImagesFound["node:14"] = true
		} else if issue.GetID() == "SNYK-CONTAINER-BASE-IMAGE-nginx:1.19-alpine-9" {
			baseImagesFound["nginx:1.19-alpine"] = true
		}
	}

	// Verify all expected base images were detected
	assert.True(t, baseImagesFound["ubuntu:18.04"], "Should detect ubuntu:18.04")
	assert.True(t, baseImagesFound["node:14"], "Should detect node:14")
	assert.True(t, baseImagesFound["nginx:1.19-alpine"], "Should detect nginx:1.19-alpine")
}

// TestSingleStageDockerfile verifies detection in a simple single-stage Dockerfile
func TestSingleStageDockerfile(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetSnykContainerEnabled(true)

	mockAPI := &MockBaseImageRemediationAPI{
		response: &BaseImageRecommendation{
			OriginalImage:     "python:3.8",
			RecommendedImage:  "python:3.11-slim",
			Reason:            "Newer Python version with security updates and smaller image size",
			SeverityReduction: "Reduces vulnerabilities and image size by 40%",
		},
		err: nil,
	}
	scanner := newMockScanner(c, mockAPI)

	tmpDir := t.TempDir()
	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	dockerfileContent := `FROM python:3.8
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "app.py"]`

	err := os.WriteFile(dockerfilePath, []byte(dockerfileContent), 0644)
	require.NoError(t, err)

	ctx := t.Context()
	issues, err := scanner.Scan(ctx, types.FilePath(dockerfilePath), types.FilePath(tmpDir), nil)

	require.NoError(t, err)
	require.Len(t, issues, 1, "Should find exactly 1 base image issue")

	issue := issues[0]
	assert.Equal(t, "SNYK-CONTAINER-BASE-IMAGE-python:3.8-0", issue.GetID())
	assert.Contains(t, issue.GetMessage(), "python:3.8")
	assert.Contains(t, issue.GetFormattedMessage(), "python:3.11-slim")

	t.Logf("Detected base image issue: %s", issue.GetMessage())
	t.Logf("Recommendation: %s", issue.GetFormattedMessage())
}

// TestDockerfileWithComments verifies that comments don't interfere with detection
func TestDockerfileWithComments(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetSnykContainerEnabled(true)

	mockAPI := &MockBaseImageRemediationAPI{
		response: &BaseImageRecommendation{
			OriginalImage:     "alpine:3.14",
			RecommendedImage:  "alpine:3.18",
			Reason:            "Latest stable Alpine version with security patches",
			SeverityReduction: "Includes critical security updates",
		},
		err: nil,
	}
	scanner := newMockScanner(c, mockAPI)

	tmpDir := t.TempDir()
	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	dockerfileContent := `# Base image for our application
# Using Alpine for smaller image size
FROM alpine:3.14

# Install dependencies
RUN apk add --no-cache nodejs npm

# Set working directory
WORKDIR /app

# Copy application files
COPY . .

# Start the application
CMD ["node", "server.js"]`

	err := os.WriteFile(dockerfilePath, []byte(dockerfileContent), 0644)
	require.NoError(t, err)

	ctx := t.Context()
	issues, err := scanner.Scan(ctx, types.FilePath(dockerfilePath), types.FilePath(tmpDir), nil)

	require.NoError(t, err)
	require.Len(t, issues, 1, "Should find exactly 1 base image issue despite comments")

	issue := issues[0]
	assert.Equal(t, "SNYK-CONTAINER-BASE-IMAGE-alpine:3.14-2", issue.GetID())

	t.Logf("Successfully detected base image with comments: %s", issue.GetMessage())
}

// TestSkipScratchImage verifies that FROM scratch is properly skipped
func TestSkipScratchImage(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetSnykContainerEnabled(true)

	mockAPI := &MockBaseImageRemediationAPI{
		response: &BaseImageRecommendation{
			OriginalImage:     "golang:1.19",
			RecommendedImage:  "golang:1.21",
			Reason:            "Newer Go version with performance improvements",
			SeverityReduction: "Includes security patches",
		},
		err: nil,
	}
	scanner := newMockScanner(c, mockAPI)

	tmpDir := t.TempDir()
	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	dockerfileContent := `FROM golang:1.19 as builder
WORKDIR /app
COPY . .
RUN go build -o app

FROM scratch
COPY --from=builder /app/app /app
ENTRYPOINT ["/app"]`

	err := os.WriteFile(dockerfilePath, []byte(dockerfileContent), 0644)
	require.NoError(t, err)

	ctx := t.Context()
	issues, err := scanner.Scan(ctx, types.FilePath(dockerfilePath), types.FilePath(tmpDir), nil)

	require.NoError(t, err)
	require.Len(t, issues, 1, "Should only find golang image, not scratch")

	issue := issues[0]
	assert.Equal(t, "SNYK-CONTAINER-BASE-IMAGE-golang:1.19-0", issue.GetID())
	assert.NotContains(t, issue.GetID(), "scratch", "Should not create issue for scratch image")

	t.Logf("Correctly skipped 'FROM scratch' and only detected: %s", issue.GetID())
}
