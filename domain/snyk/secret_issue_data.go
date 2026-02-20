/*
 * © 2026 Snyk Limited
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

package snyk

import (
	"encoding/json"

	"github.com/pkg/errors"

	"github.com/snyk/snyk-ls/internal/product"
)

type SecretIssueData struct {
	// Key is an opaque key used for aggregating the finding across test executions
	Key string `json:"key"`
	// Title is the human-readable name of the secret type (e.g. "AWS Access Token")
	Title string `json:"title"`
	// Message is the longer description / help text for the finding
	Message string `json:"message"`
	// RuleId identifies the secret detection rule (e.g. "aws-access-token")
	RuleId string `json:"ruleId"`
	// RuleName is the human-readable rule name (e.g. "AWS Access Token")
	RuleName string `json:"ruleName"`
	// CWE lists the CWE identifiers associated with this secret finding
	CWE []string `json:"cwe"`
	// Categories applied to the rule (e.g. ["Security"])
	Categories []string `json:"categories"`
	// Cols is the column range [startCol, endCol] (0-based)
	Cols CodePoint `json:"cols"`
	// Rows is the row range [startLine, endLine] (0-based)
	Rows CodePoint `json:"rows"`
	// LocationsCount is the number of locations where the secret is found
	LocationsCount int `json:"locationsCount"`
}

func (s SecretIssueData) GetKey() string {
	return s.Key
}

func (s SecretIssueData) GetTitle() string {
	return s.Title
}

func (s SecretIssueData) IsFixable() bool {
	return false
}

func (s SecretIssueData) GetFilterableIssueType() product.FilterableIssueType {
	return product.FilterableIssueTypeSecrets
}

func (s SecretIssueData) MarshalJSON() ([]byte, error) {
	type IssueAlias SecretIssueData
	aliasStruct := struct {
		Type string `json:"type"`
		*IssueAlias
	}{
		Type:       "SecretIssueData",
		IssueAlias: (*IssueAlias)(&s),
	}
	data, err := json.Marshal(aliasStruct)
	return data, errors.Wrap(err, "error marshaling SecretIssueData")
}
