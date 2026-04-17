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

package code

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/rs/zerolog"

	codeClientSarif "github.com/snyk/code-client-go/sarif"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/internal/types"
)

// ConvertSARIFJSONToIssues converts SARIF JSON output to Issues without requiring a full scanner instance
// This is a simplified version for use by MCP and other tools that need conversion without full scanner
// basePath is the absolute path where the scan was run (optional - if empty, paths remain relative)
func ConvertSARIFJSONToIssues(engine workflow.Engine, logger *zerolog.Logger, hoverVerbosity int, sarifJSON []byte, basePath string) ([]types.Issue, error) {
	var head sarifDocumentHead
	if err := json.Unmarshal(sarifJSON, &head); err != nil {
		return nil, fmt.Errorf("failed to parse SARIF JSON: %w", err)
	}
	if len(head.Runs) == 0 {
		return nil, nil
	}
	run := codeClientSarif.Run{
		Tool:       head.Runs[0].Tool,
		Properties: head.Runs[0].Properties,
		Results:    nil,
	}
	var sarifResponse codeClientSarif.SarifResponse
	sarifResponse.Sarif.Schema = head.Schema
	sarifResponse.Sarif.Version = head.Version
	sarifResponse.Sarif.Runs = []codeClientSarif.Run{run}

	converter := SarifConverter{sarif: sarifResponse, logger: logger, hoverVerbosity: hoverVerbosity, engine: engine}
	ruleLink := createRuleLink()
	baseDir := types.FilePath(basePath)

	var issues []types.Issue
	var errs error
	err := streamFirstRunResults(sarifJSON, func(res codeClientSarif.Result) error {
		var err2 error
		issues, err2 = converter.appendIssuesForResult(run, res, baseDir, ruleLink, issues)
		errs = errors.Join(errs, err2)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse SARIF JSON: %w", err)
	}
	if errs != nil {
		return nil, fmt.Errorf("failed to convert SARIF to issues: %w", errs)
	}
	return issues, nil
}
