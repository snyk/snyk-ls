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

package snyk

import (
	"encoding/json"

	"github.com/snyk/snyk-ls/internal/product"
)

type CodeIssueData struct {
	// Unique key identifying an issue in the whole result set
	Key                string             `json:"key"`
	Title              string             `json:"title"`
	Message            string             `json:"message"`
	Rule               string             `json:"rule"`
	RuleId             string             `json:"ruleId"`
	RepoDatasetSize    int                `json:"repoDatasetSize"`
	ExampleCommitFixes []ExampleCommitFix `json:"exampleCommitFixes"`
	CWE                []string           `json:"cwe"`
	Text               string             `json:"text"`
	Markers            []Marker           `json:"markers,omitempty"`
	Cols               CodePoint          `json:"cols"`
	Rows               CodePoint          `json:"rows"`
	IsSecurityType     bool               `json:"isSecurityType"`
	IsAutofixable      bool               `json:"isAutofixable"`
	PriorityScore      int                `json:"priorityScore"`
	HasAIFix           bool               `json:"hasAIFix"`
	DataFlow           []DataFlowElement  `json:"dataFlow,omitempty"`
	Details            string             `json:"details"`
}

func (c CodeIssueData) GetKey() string {
	return c.Key
}

func (c CodeIssueData) GetTitle() string {
	return c.Title
}

func (c CodeIssueData) IsFixable() bool {
	return c.HasAIFix
}

func (c CodeIssueData) GetFilterableIssueType() product.FilterableIssueType {
	if c.IsSecurityType {
		return product.FilterableIssueTypeCodeSecurity
	}
	return product.FilterableIssueTypeCodeQuality
}

func (c CodeIssueData) MarshalJSON() ([]byte, error) {
	type IssueAlias CodeIssueData
	aliasStruct := struct {
		Type string `json:"type"`
		*IssueAlias
	}{
		Type:       "CodeIssueData",
		IssueAlias: (*IssueAlias)(&c),
	}
	data, err := json.Marshal(aliasStruct)
	return data, err
}
