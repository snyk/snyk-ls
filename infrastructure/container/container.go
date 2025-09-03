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

// Package container implements Snyk Container scanning for base image recommendations
package container

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/snyk/go-application-framework/pkg/networking"

	"github.com/snyk/snyk-ls/application/config"
	dockerfileparser "github.com/snyk/snyk-ls/ast/dockerfile"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/types"
)

const (
	containerDocumentationUrl = "https://docs.snyk.io/products/snyk-container"
)

var containerDocUrl *url.URL

func init() {
	containerDocUrl, _ = url.Parse(containerDocumentationUrl)
}

type Scanner struct {
	config        *config.Config
	errorReporter error_reporting.ErrorReporter
	instrumentor  performance.Instrumentor
	apiClient     BaseImageRemediationAPI
	parser        dockerfileparser.Parser
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
type DockerDepsRemediationAPI struct {
	networkAccess networking.NetworkAccess
	config        *config.Config
}

func (d *DockerDepsRemediationAPI) GetBaseImageRecommendation(ctx context.Context, baseImage string) (*BaseImageRecommendation, error) {
	// Construct the API URL with query parameters
	apiURL := fmt.Sprintf("%s/docker-deps/recommended-base-image", d.config.SnykApi())
	parsedURL, err := url.Parse(apiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse API URL: %w", err)
	}

	// Add query parameters
	q := parsedURL.Query()
	q.Set("baseImage", baseImage)
	parsedURL.RawQuery = q.Encode()

	// Use GAF NetworkAccess to make the request
	// This automatically handles authentication, headers, and other network configuration
	resp, err := d.networkAccess.GetHttpClient().Get(parsedURL.String())
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

func New(c *config.Config, instrumentor performance.Instrumentor, errorReporter error_reporting.ErrorReporter, networkAccess networking.NetworkAccess) *Scanner {
	apiClient := &DockerDepsRemediationAPI{
		networkAccess: networkAccess,
		config:        c,
	}

	logger := c.Logger()
	parser := dockerfileparser.New(logger)

	return &Scanner{
		config:        c,
		errorReporter: errorReporter,
		instrumentor:  instrumentor,
		apiClient:     apiClient,
		parser:        parser,
	}
}

func (sc *Scanner) IsEnabled() bool {
	return sc.config.IsSnykContainerEnabled()
}

func (sc *Scanner) Product() product.Product {
	return product.ProductContainer
}

func (sc *Scanner) Scan(ctx context.Context, path types.FilePath, folderPath types.FilePath, folderConfig *types.FolderConfig) (issues []types.Issue, err error) {
	method := "container.Scan"
	logger := sc.config.Logger().With().Str("method", method).Logger()

	// Start instrumentation span
	span := sc.instrumentor.StartSpan(ctx, method)
	defer sc.instrumentor.Finish(span)
	logger.Debug().Str("method", method).Msg("started.")
	defer logger.Debug().Str("method", method).Msg("done.")

	// Check for cancellation
	if ctx.Err() != nil {
		logger.Debug().Msg("Canceling Container scan - Container scanner received cancellation signal")
		return []types.Issue{}, nil
	}

	ctx, cancel := context.WithCancel(span.Context())
	defer cancel()

	// Setup progress tracking
	p := progress.NewTracker(true)
	go func() { p.CancelOrDone(cancel, ctx.Done()) }()
	p.BeginUnquantifiableLength("Scanning for Snyk Container issues", string(path))
	defer p.EndWithMessage("Snyk Container scan completed.")

	fileInfo, err := os.Stat(string(path))
	if err != nil {
		sc.errorReporter.CaptureErrorAndReportAsIssue(path, err)
		logger.Err(err).Str("method", method).Msg("Error while getting file info.")
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
		sc.errorReporter.CaptureErrorAndReportAsIssue(path, err)
		logger.Err(err).Str("method", method).Msg("Error while reading file")
		return []types.Issue{}, err
	}

	// Check for cancellation before processing
	if ctx.Err() != nil {
		return []types.Issue{}, nil
	}

	return sc.scanDockerFile(ctx, string(path), string(bytes), folderPath)
}

func (sc *Scanner) isDockerFile(fileName string) bool {
	lowerFileName := strings.ToLower(fileName)
	return lowerFileName == "dockerfile" ||
		strings.HasPrefix(lowerFileName, "dockerfile.") ||
		lowerFileName == "docker-compose.yml" ||
		lowerFileName == "docker-compose.yaml"
}

func (sc *Scanner) scanDockerFile(ctx context.Context, filePath string, content string, folderPath types.FilePath) ([]types.Issue, error) {
	method := "container.scanDockerFile"
	logger := sc.config.Logger().With().Str("method", method).Logger()

	// Start instrumentation span for Docker file scanning
	span := sc.instrumentor.StartSpan(ctx, method)
	defer sc.instrumentor.Finish(span)

	// Extract requestID from span for tracing
	requestID := span.GetTraceId()
	logger.Info().Str("requestId", requestID).Str("filePath", filePath).Msg("Starting Container Docker file analysis.")

	// Check for cancellation
	if ctx.Err() != nil {
		logger.Debug().Str("requestId", requestID).Msg("Container Docker file scan canceled")
		return []types.Issue{}, nil
	}

	// Parse Dockerfile using AST parser
	tree := sc.parser.Parse([]byte(content), filePath)

	// First pass: collect all base images to analyze from AST
	type baseImageInfo struct {
		image   string
		lineNum int
		line    string
	}

	var imagesToAnalyze []baseImageInfo
	lines := strings.Split(strings.ReplaceAll(content, "\r", ""), "\n")

	// Extract FROM nodes from AST
	for _, fromNode := range tree.Root.Children {
		if fromNode.Name != "FROM" {
			continue
		}

		lineNum := fromNode.Line
		line := ""
		if lineNum < len(lines) {
			line = lines[lineNum]
		}

		imagesToAnalyze = append(imagesToAnalyze, baseImageInfo{
			image:   fromNode.Value,
			lineNum: lineNum,
			line:    line,
		})
	}

	if len(imagesToAnalyze) == 0 {
		logger.Info().Str("requestId", requestID).Msg("No base images found to analyze")
		return []types.Issue{}, nil
	}

	// Second pass: parallelize API calls using goroutines
	type result struct {
		info           baseImageInfo
		recommendation *BaseImageRecommendation
		err            error
	}

	resultChan := make(chan result, len(imagesToAnalyze))
	for _, info := range imagesToAnalyze {
		go func(imageInfo baseImageInfo) {
			// Check for cancellation before making API call
			if ctx.Err() != nil {
				resultChan <- result{info: imageInfo, err: ctx.Err()}
				return
			}

			logger.Debug().Str("requestId", requestID).Str("baseImage", imageInfo.image).Msg("Analyzing base image")
			recommendation, err := sc.apiClient.GetBaseImageRecommendation(ctx, imageInfo.image)
			resultChan <- result{
				info:           imageInfo,
				recommendation: recommendation,
				err:            err,
			}
		}(info)
	}

	// Collect results
	issues := make([]types.Issue, 0, len(imagesToAnalyze))
	for i := 0; i < len(imagesToAnalyze); i++ {
		// Check for cancellation while collecting results
		if ctx.Err() != nil {
			logger.Debug().Str("requestId", requestID).Msg("Container Docker file scan canceled during processing")
			return []types.Issue{}, nil
		}

		res := <-resultChan
		if res.err != nil {
			sc.errorReporter.CaptureErrorAndReportAsIssue(types.FilePath(filePath), res.err)
			logger.Err(res.err).Str("requestId", requestID).Str("method", method).Str("baseImage", res.info.image).Msg("Error getting base image recommendation")
			continue
		}

		// Create issue with code action to replace base image
		issue := sc.createBaseImageIssue(filePath, res.info.lineNum, res.info.line, res.info.image, res.recommendation, folderPath)
		issues = append(issues, issue)
	}

	logger.Info().Str("requestId", requestID).Int("issuesFound", len(issues)).Msg("Container Docker file analysis completed.")
	return issues, nil
}

func (sc *Scanner) createBaseImageIssue(filePath string, lineNum int, line string, baseImage string, recommendation *BaseImageRecommendation, folderPath types.FilePath) types.Issue {
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
		fmt.Sprintf("Upgrade to %s (Snyk)", recommendation.RecommendedImage),
		workspaceEdit,
		nil,
	)
	if err != nil {
		sc.errorReporter.CaptureErrorAndReportAsIssue(types.FilePath(filePath), err)
		log.Err(err).Str("method", "container.createBaseImageIssue").Msg("Error creating code action")
	}

	var codeActions []types.CodeAction
	if codeAction != nil {
		codeActions = []types.CodeAction{codeAction}
	}

	// Create issue
	// TODO: Use highest severity from base image vulnerabilities when API provides this information
	issue := &snyk.Issue{
		ID:                  fmt.Sprintf("SNYK-CONTAINER-BASE-IMAGE-%s-%d", baseImage, lineNum),
		Severity:            types.Medium,
		IssueType:           types.ContainerIssue,
		Range:               r,
		Message:             fmt.Sprintf("Base image '%s' may have security vulnerabilities", baseImage),
		FormattedMessage:    sc.getFormattedMessage(baseImage, recommendation),
		AffectedFilePath:    types.FilePath(filePath),
		ContentRoot:         folderPath,
		Product:             product.ProductContainer,
		References:          []types.Reference{},
		IssueDescriptionURL: containerDocUrl,
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
