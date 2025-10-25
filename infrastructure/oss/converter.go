/*
 * © 2024 Snyk Limited
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
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

// ConvertJSONToIssues converts OSS JSON output to Issue objects with optional learn service
// This is a standalone version of CLIScanner.unmarshallAndRetrieveAnalysis
func ConvertJSONToIssues(logger *zerolog.Logger, jsonData []byte, learnService learn.Service, workDir string) ([]types.Issue, error) {
	// Call the standalone version of unmarshallAndRetrieveAnalysis
	issues, _ := UnmarshallAndRetrieveAnalysis(
		context.Background(),
		jsonData,
		types.FilePath(workDir),
		"",
		logger,
		error_reporting.NewTestErrorReporter(),
		learnService,
		make(map[string][]types.Issue), // empty package issue cache
		false,
		config.FormatMd,
	)

	return issues, nil
}

// UnmarshallAndRetrieveAnalysis is a standalone version of CLIScanner.unmarshallAndRetrieveAnalysis
// that can be used without a CLIScanner instance
//   - scanOutput: the output of the scan (can be either a []byte or []workflow.Data)
func UnmarshallAndRetrieveAnalysis(
	ctx context.Context,
	scanOutput any,
	workDir types.FilePath,
	path types.FilePath,
	logger *zerolog.Logger,
	errorReporter error_reporting.ErrorReporter,
	learnService learn.Service,
	packageIssueCache map[string][]types.Issue,
	readFiles bool,
	format string,
) ([]types.Issue, error) {
	if ctx.Err() != nil {
		return nil, nil
	}

	// new ostest workflow result processing
	if output, ok := scanOutput.([]workflow.Data); ok {
		return processOsTestWorkFlowData(ctx, output, packageIssueCache)
	}

	// unchanged legacy workflow
	var allIssues []types.Issue
	scanOutputBytes, ok := scanOutput.([]byte)
	if !ok || len(scanOutputBytes) == 0 {
		return nil, nil
	}

	scanResults, err := UnmarshallOssJson(scanOutputBytes)
	if err != nil {
		errorReporter.CaptureErrorAndReportAsIssue(path, err)
		return nil, nil
	}

	for _, scanResult := range scanResults {
		targetFilePath := getAbsTargetFilePath(logger, scanResult.Path, scanResult.DisplayTargetFile, workDir, path)

		var fileContent []byte

		if targetFilePath != "" && readFiles && uri.IsRegularFile(targetFilePath) {
			fileContent, err = os.ReadFile(string(targetFilePath))
			if err != nil {
				logger.Error().Err(err).Str("filePath", string(targetFilePath)).Msg("Failed to read file")
			}
		}

		issues := convertScanResultToIssues(logger, &scanResult, workDir, targetFilePath, fileContent, learnService, errorReporter, packageIssueCache, format)
		allIssues = append(allIssues, issues...)
	}

	return allIssues, nil
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
