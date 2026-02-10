/*
 * © 2024-2025 Snyk Limited
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

// Package oss implements the OSS scanner
package oss

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

// ConvertJSONToIssues converts OSS JSON output to Issue objects with optional learn service
// This is a standalone version of CLIScanner.unmarshallAndRetrieveAnalysis
func ConvertJSONToIssues(logger *zerolog.Logger, jsonData []byte, learnService learn.Service, workDir string) ([]types.Issue, error) {
	issues, err := ProcessScanResults(context.Background(), jsonData, error_reporting.NewTestErrorReporter(), learnService, make(map[string][]types.Issue), false, config.FormatMd)

	return issues, err
}

// ProcessScanResults takes the results from the scanner and transforms them into
// our internal issue format. It also populates the given package cache with the
// found problems per package.
//   - scanOutput: the output of the scan (can be either a []byte or []workflow.Data)
func ProcessScanResults(ctx context.Context, scanOutput any, errorReporter error_reporting.ErrorReporter, learnService learn.Service, packageIssueCache map[string][]types.Issue, readFiles bool, format string) ([]types.Issue, error) {
	if ctx.Err() != nil {
		return nil, nil
	}
	logger := ctx2.LoggerFromContext(ctx).With().Str("method", "ProcessScanResults").Logger()
	deps, found := ctx2.DependenciesFromContext(ctx)
	c := config.CurrentConfig()
	if found {
		ctxConfig, ok := deps[ctx2.DepConfig].(*config.Config)
		if !ok {
			return nil, errors.New("failed to get config from context")
		}
		c = ctxConfig
	}
	workDir := ctx2.WorkDirFromContext(ctx)
	filePath := ctx2.FilePathFromContext(ctx)

	// new ostest workflow result processing
	if output, ok := scanOutput.([]workflow.Data); ok {
		return processOsTestWorkFlowData(ctx, output, packageIssueCache, c, workDir, filePath, readFiles, learnService, errorReporter, format)
	}

	// unchanged legacy workflow
	var allIssues []types.Issue
	scanOutputBytes, ok := scanOutput.([]byte)
	if !ok || len(scanOutputBytes) == 0 {
		return nil, nil
	}

	scanResults, err := UnmarshallOssJson(scanOutputBytes)
	if err != nil {
		errorReporter.CaptureErrorAndReportAsIssue(filePath, err)
		return nil, nil
	}

	for _, scanResult := range scanResults {
		targetFilePath := getAbsTargetFilePath(&logger, scanResult.Path, scanResult.DisplayTargetFile, workDir, filePath)

		fileContent := getFileContent(targetFilePath, readFiles, logger)

		issues := convertScanResultToIssues(c, &scanResult, workDir, targetFilePath, fileContent, learnService, errorReporter, packageIssueCache, format)
		allIssues = append(allIssues, issues...)
	}

	return allIssues, nil
}

func getFileContent(targetFilePath types.FilePath, readFiles bool, logger zerolog.Logger) []byte {
	if targetFilePath != "" && readFiles && uri.IsRegularFile(targetFilePath) {
		fc, err := os.ReadFile(string(targetFilePath))
		if err != nil {
			logger.Error().Err(err).Str("filePath", string(targetFilePath)).Msg("Failed to read file")
		}
		return fc
	}
	return []byte{}
}

// UnmarshallOssJson is a standalone version of CLIScanner.unmarshallOssJson
func UnmarshallOssJson(res []byte) (scanResults []scanResult, err error) {
	output := string(res)
	if strings.HasPrefix(output, "[") {
		err = json.Unmarshal(res, &scanResults)
		if err != nil {
			err = errors.Join(err, fmt.Errorf("couldn't unmarshal CLI response. Input: %s", output))
			return nil, err
		}
	} else {
		var result scanResult
		err = json.Unmarshal(res, &result)
		if err != nil {
			err = errors.Join(err, fmt.Errorf("couldn't unmarshal CLI response. Input: %s", output))
			return nil, err
		}
		scanResults = append(scanResults, result)
	}
	return scanResults, err
}
