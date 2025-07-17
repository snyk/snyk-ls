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
	"fmt"
	"github.com/rs/zerolog"

	codeClientSarif "github.com/snyk/code-client-go/sarif"

	"github.com/snyk/snyk-ls/internal/types"
)

// ConvertSARIFJSONToIssues converts SARIF JSON output to Issues without requiring a full scanner instance
// This is a simplified version for use by MCP and other tools that need conversion without full scanner
// basePath is the absolute path where the scan was run (optional - if empty, paths remain relative)
func ConvertSARIFJSONToIssues(logger *zerolog.Logger, hoverVerbosity int, sarifJSON []byte, basePath string) ([]types.Issue, error) {
	var sarifResponse codeClientSarif.SarifResponse

	err := json.Unmarshal(sarifJSON, &sarifResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SARIF JSON: %w", err)
	}

	converter := SarifConverter{sarif: sarifResponse, logger: logger, hoverVerbosity: hoverVerbosity}

	// Convert with provided base path (or empty for relative paths)
	issues, err := converter.toIssues(types.FilePath(basePath))
	if err != nil {
		return nil, fmt.Errorf("failed to convert SARIF to issues: %w", err)
	}

	return issues, nil
}
