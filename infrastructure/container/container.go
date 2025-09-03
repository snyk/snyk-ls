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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

const (
	containerDocumentationUrl = "https://docs.snyk.io/products/snyk-container"
)

type Scanner struct {
	config        *config.Config
	errorReporter error_reporting.ErrorReporter
	docUrl        *url.URL
	httpClient    func() *http.Client
	apiClient     BaseImageRemediationAPI
}

// BaseImageRemediationAPI defines the interface for base image remediation API
type BaseImageRemediationAPI interface {
	GetBaseImageRecommendation(ctx context.Context, baseImage string) (*BaseImageRecommendation, error)
}

// BaseImageRecommendation represents a recommended base image upgrade
type BaseImageRecommendation struct {
	OriginalImage     string
	RecommendedImage  string
	Reason            string
	SeverityReduction string
}

// DockerDepsResponse represents the response from docker-deps recommended-base-image endpoint
type DockerDepsResponse struct {
	BaseImage         string                `json:"baseImage"`
	Recommendations   []ImageRecommendation `json:"recommendations"`
	MinorUpgrades     []ImageRecommendation `json:"minorUpgrades"`
	MajorUpgrades     []ImageRecommendation `json:"majorUpgrades"`
	AlternativeImages []ImageRecommendation `json:"alternativeImages"`
}

// ImageRecommendation represents a single image recommendation
type ImageRecommendation struct {
	Image  string `json:"image"`
	Reason string `json:"reason"`
}

// DockerDepsRemediationAPI is a real implementation that calls the docker-deps API
type DockerDepsRemediationAPI struct {
	httpClient func() *http.Client
	config     *config.Config
}

func (d *DockerDepsRemediationAPI) GetBaseImageRecommendation(ctx context.Context, baseImage string) (*BaseImageRecommendation, error) {
	// Construct the API URL
	apiURL := fmt.Sprintf("%s/docker-deps/recommended-base-image", d.config.SnykApi())

	// Create the request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add query parameters
	q := req.URL.Query()
	q.Set("baseImage", baseImage)
	req.URL.RawQuery = q.Encode()

	// Add headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-snyk-ide", "snyk-ls-"+config.Version)

	// Make the request
	resp, err := d.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make API request: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the response
	var dockerDepsResp DockerDepsResponse
	if err := json.NewDecoder(resp.Body).Decode(&dockerDepsResp); err != nil {
		return nil, fmt.Errorf("failed to parse API response: %w", err)
	}

	// Extract the minor version upgrade recommendation
	var recommendedImage string
	var reason string

	if len(dockerDepsResp.MinorUpgrades) > 0 {
		// For version 1, use minor upgrades as they are safer
		recommendedImage = dockerDepsResp.MinorUpgrades[0].Image
		reason = dockerDepsResp.MinorUpgrades[0].Reason
	} else {
		return nil, fmt.Errorf("no minor version recommendations available for base image: %s", baseImage)
	}

	return &BaseImageRecommendation{
		OriginalImage:     baseImage,
		RecommendedImage:  recommendedImage,
		Reason:            reason,
		SeverityReduction: "Reduces known vulnerabilities by upgrading to a more secure version",
	}, nil
}

// PlaceholderRemediationAPI is a placeholder implementation of BaseImageRemediationAPI
type PlaceholderRemediationAPI struct{}

func (p *PlaceholderRemediationAPI) GetBaseImageRecommendation(ctx context.Context, baseImage string) (*BaseImageRecommendation, error) {
	// Placeholder implementation - returns a default recommendation
	return &BaseImageRecommendation{
		OriginalImage:     baseImage,
		RecommendedImage:  "ubuntu:22.04-slim", // Default safe recommendation
		Reason:            "Recommended secure base image with latest security patches",
		SeverityReduction: "Reduces known vulnerabilities by upgrading to latest patched version",
	}, nil
}

func New(c *config.Config, errorReporter error_reporting.ErrorReporter, httpClient func() *http.Client) *Scanner {
	docUrl, _ := url.Parse(containerDocumentationUrl)

	// Use real API implementation
	apiClient := &DockerDepsRemediationAPI{
		httpClient: httpClient,
		config:     c,
	}

	return &Scanner{
		config:        c,
		errorReporter: errorReporter,
		docUrl:        docUrl,
		httpClient:    httpClient,
		apiClient:     apiClient,
	}
}

func (sc *Scanner) IsEnabled() bool {
	return sc.config.IsSnykContainerEnabled()
}

func (sc *Scanner) Product() product.Product {
	return product.ProductContainer
}

func (sc *Scanner) Scan(ctx context.Context, path types.FilePath, folderPath types.FilePath, folderConfig *types.FolderConfig) (issues []types.Issue, err error) {
	fileInfo, err := os.Stat(string(path))
	if err != nil {
		sc.errorReporter.CaptureError(err)
		log.Err(err).Str("method", "container.Scan").Msg("Error while getting file info.")
		return []types.Issue{}, err
	}

	if fileInfo.IsDir() {
		// Container scanner operates on file basis, not directories
		return []types.Issue{}, nil
	}

	// Only scan Dockerfile and docker-compose files
	fileName := strings.ToLower(fileInfo.Name())
	if !sc.isDockerFile(fileName) {
		return []types.Issue{}, nil
	}

	bytes, err := os.ReadFile(string(path))
	if err != nil {
		sc.errorReporter.CaptureError(err)
		log.Err(err).Str("method", "container.Scan").Msg("Error while reading file")
		return []types.Issue{}, err
	}

	return sc.scanDockerFile(ctx, string(path), string(bytes))
}

func (sc *Scanner) isDockerFile(fileName string) bool {
	lowerFileName := strings.ToLower(fileName)
	return lowerFileName == "dockerfile" ||
		strings.HasPrefix(lowerFileName, "dockerfile.") ||
		lowerFileName == "docker-compose.yml" ||
		lowerFileName == "docker-compose.yaml"
}

func (sc *Scanner) scanDockerFile(ctx context.Context, filePath string, content string) ([]types.Issue, error) {
	issues := make([]types.Issue, 0)

	// Regex to match FROM instructions in Dockerfile
	fromRegex := regexp.MustCompile(`(?i)^\s*FROM\s+([^\s]+)`)

	lines := strings.Split(strings.ReplaceAll(content, "\r", ""), "\n")
	for lineNum, line := range lines {
		matches := fromRegex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		baseImage := matches[1]
		// Skip scratch and multi-stage build references
		if baseImage == "scratch" || strings.Contains(baseImage, " as ") {
			continue
		}

		// Get recommendation from API
		recommendation, err := sc.apiClient.GetBaseImageRecommendation(ctx, baseImage)
		if err != nil {
			sc.errorReporter.CaptureError(err)
			log.Err(err).Str("method", "container.scanDockerFile").Msg("Error getting base image recommendation")
			continue
		}

		// Create issue with code action to replace base image
		issue := sc.createBaseImageIssue(filePath, lineNum, line, baseImage, recommendation)
		issues = append(issues, issue)
	}

	return issues, nil
}

func (sc *Scanner) createBaseImageIssue(filePath string, lineNum int, line string, baseImage string, recommendation *BaseImageRecommendation) types.Issue {
	// Find the position of the base image in the line
	fromIndex := strings.Index(strings.ToLower(line), "from")
	imageStart := fromIndex + 4 // "FROM" length
	for imageStart < len(line) && line[imageStart] == ' ' {
		imageStart++ // Skip whitespace
	}
	imageEnd := imageStart + len(baseImage)

	r := types.Range{
		Start: types.Position{Line: lineNum, Character: imageStart},
		End:   types.Position{Line: lineNum, Character: imageEnd},
	}

	// Create text edit for code action
	textEdit := types.TextEdit{
		Range:   r,
		NewText: recommendation.RecommendedImage,
	}

	workspaceEdit := &types.WorkspaceEdit{
		Changes: map[string][]types.TextEdit{
			filePath: {textEdit},
		},
	}

	codeAction, err := snyk.NewCodeAction(
		fmt.Sprintf("Upgrade to %s", recommendation.RecommendedImage),
		workspaceEdit,
		nil,
	)
	if err != nil {
		sc.errorReporter.CaptureError(err)
		log.Err(err).Str("method", "container.createBaseImageIssue").Msg("Error creating code action")
	}

	var codeActions []types.CodeAction
	if codeAction != nil {
		codeActions = []types.CodeAction{codeAction}
	}

	// Create issue
	issue := &snyk.Issue{
		ID:                  fmt.Sprintf("SNYK-CONTAINER-BASE-IMAGE-%s", baseImage),
		Severity:            types.Medium,
		IssueType:           types.ContainerIssue,
		Range:               r,
		Message:             fmt.Sprintf("Base image '%s' may have security vulnerabilities", baseImage),
		FormattedMessage:    sc.getFormattedMessage(baseImage, recommendation),
		AffectedFilePath:    types.FilePath(filePath),
		ContentRoot:         types.FilePath(filePath),
		Product:             product.ProductContainer,
		References:          []types.Reference{},
		IssueDescriptionURL: sc.docUrl,
		CodeActions:         codeActions,
		CodelensCommands:    []types.CommandData{},
		Ecosystem:           "docker",
		CWEs:                []string{},
		CVEs:                []string{},
	}

	return issue
}

func (sc *Scanner) getFormattedMessage(baseImage string, recommendation *BaseImageRecommendation) string {
	return fmt.Sprintf(`## Container Base Image Recommendation

**Current Image:** %s  
**Recommended Image:** %s

**Reason:** %s

**Benefits:** %s

[Learn more about Snyk Container](%s)`,
		baseImage,
		recommendation.RecommendedImage,
		recommendation.Reason,
		recommendation.SeverityReduction,
		containerDocumentationUrl)
}
