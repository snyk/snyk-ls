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

	codeClientSarif "github.com/snyk/code-client-go/sarif"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
)

// ConvertSARIFJSONToIssues converts SARIF JSON output to Issues without requiring a full scanner instance
// This is a simplified version for use by MCP and other tools that need conversion without full scanner
// Note: This uses a simplified path (no base directory) so file paths will be relative
func ConvertSARIFJSONToIssues(sarifJSON []byte) ([]types.Issue, error) {
	var sarifResponse codeClientSarif.SarifResponse

	err := json.Unmarshal(sarifJSON, &sarifResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SARIF JSON: %w", err)
	}

	// Create a converter with default config
	c := config.CurrentConfig()
	converter := SarifConverter{sarif: sarifResponse, c: c}

	// Convert with empty base directory - paths will be relative
	issues, err := converter.toIssues(types.FilePath(""))
	if err != nil {
		return nil, fmt.Errorf("failed to convert SARIF to issues: %w", err)
	}

	return issues, nil
}
