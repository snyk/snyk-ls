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

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

// ConvertJSONToIssuesWithoutDependencies converts OSS JSON output to Issues using the existing converter
// with minimal dependencies (test error reporter)
func ConvertJSONToIssuesWithoutDependencies(jsonOutput []byte) ([]types.Issue, error) {
	return ConvertJSONToIssuesWithLearnService(jsonOutput, nil)
}

// ConvertJSONToIssuesWithLearnService converts OSS JSON output to Issue objects with optional learn service
// This is a standalone version of CLIScanner.unmarshallAndRetrieveAnalysis
func ConvertJSONToIssuesWithLearnService(jsonData []byte, learnService learn.Service) ([]types.Issue, error) {
	c := config.CurrentConfig()
	if c == nil {
		c = config.New()
		config.SetCurrentConfig(c)
	}

	// Call the standalone version of unmarshallAndRetrieveAnalysis
	issues := UnmarshallAndRetrieveAnalysis(
		context.Background(),
		jsonData,
		"", // workDir
		"", // path
		c,
		error_reporting.NewTestErrorReporter(),
		learnService,
		make(map[string][]types.Issue), // empty package issue cache
		false,                          // readFiles
	)

	return issues, nil
}

// UnmarshallAndRetrieveAnalysis is a standalone version of CLIScanner.unmarshallAndRetrieveAnalysis
// that can be used without a CLIScanner instance
func UnmarshallAndRetrieveAnalysis(
	ctx context.Context,
	res []byte,
	workDir types.FilePath,
	path types.FilePath,
	c *config.Config,
	errorReporter error_reporting.ErrorReporter,
	learnService learn.Service,
	packageIssueCache map[string][]types.Issue,
	readFiles bool,
) []types.Issue {
	logger := c.Logger().With().Str("method", "UnmarshallAndRetrieveAnalysis").Logger()
	if ctx.Err() != nil {
		return nil
	}

	scanResults, err := UnmarshallOssJson(res)
	if err != nil {
		errorReporter.CaptureErrorAndReportAsIssue(path, err)
		return nil
	}

	var allIssues []types.Issue
	for _, scanResult := range scanResults {
		targetFilePath := getAbsTargetFilePath(c, scanResult, workDir, path)

		var fileContent []byte

		if targetFilePath != "" && readFiles && uri.IsRegularFile(targetFilePath) {
			fileContent, err = os.ReadFile(string(targetFilePath))
			if err != nil {
				logger.Error().Err(err).Str("filePath", string(targetFilePath)).Msg("Failed to read file")
			}
		}

		issues := convertScanResultToIssues(c, &scanResult, workDir, targetFilePath, fileContent, learnService, errorReporter, packageIssueCache)
		allIssues = append(allIssues, issues...)
	}

	return allIssues
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
