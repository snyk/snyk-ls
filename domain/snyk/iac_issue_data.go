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

import "encoding/json"

type IaCIssueData struct {
	// Unique key identifying an issue in the whole result set
	Key string `json:"key"`
	// Title: title of the issue
	Title string `json:"title"`
	// PublicID: unique identifier for the issue; it is the same as the ScanIssue.ID
	PublicId string `json:"publicId"`
	// Documentation is a URL which is constructed from the PublicID (e.g. https://security.snyk.io/rules/cloud/SNYK-CC-K8S-13)
	Documentation string `json:"documentation"`
	// LineNumber: line number of the issue in the file
	LineNumber int `json:"lineNumber"`
	// Issue: will contain the issue description
	Issue string `json:"issue"`
	// Impact: will contain the impact description
	Impact string `json:"impact"`
	// Resolve: will contain the resolution description (not to be confused with Remediation)
	Resolve string `json:"resolve"`
	// Path: path to the issue in the file
	Path []string `json:"path"`
	// References: List of reference URLs
	References []string `json:"references,omitempty"`
	// CustomUIContent: IaC HTML template
	CustomUIContent string `json:"customUIContent"`
}

func (i IaCIssueData) GetKey() string {
	return i.Key
}

func (i IaCIssueData) GetTitle() string {
	return i.Title
}

func (i IaCIssueData) IsFixable() bool {
	return false
}

func (i IaCIssueData) MarshalJSON() ([]byte, error) {
	type IssueAlias IaCIssueData
	aliasStruct := struct {
		Type string `json:"type"`
		*IssueAlias
	}{
		Type:       "IaCIssueData",
		IssueAlias: (*IssueAlias)(&i),
	}
	data, err := json.Marshal(aliasStruct)
	return data, err
}
