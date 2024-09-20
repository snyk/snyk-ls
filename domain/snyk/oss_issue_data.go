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

type OssIssueData struct {
	Key                string             `json:"key"`
	Title              string             `json:"title"`
	Name               string             `json:"name"`
	LineNumber         int                `json:"lineNumber"`
	Identifiers        Identifiers        `jsom:"identifiers"`
	Description        string             `json:"description"`
	References         []Reference        `json:"references,omitempty"`
	Version            string             `json:"version"`
	License            string             `json:"license,omitempty"`
	PackageManager     string             `json:"packageManager"`
	PackageName        string             `json:"packageName"`
	From               []string           `json:"from"`
	FixedIn            []string           `json:"fixedIn,omitempty"`
	UpgradePath        []any              `json:"upgradePath,omitempty"`
	IsUpgradable       bool               `json:"isUpgradable,omitempty"`
	CVSSv3             string             `json:"CVSSv3,omitempty"`
	CvssScore          float64            `json:"cvssScore,omitempty"`
	Exploit            string             `json:"exploit,omitempty"`
	IsPatchable        bool               `json:"isPatchable"`
	ProjectName        string             `json:"projectName"`
	DisplayTargetFile  string             `json:"displayTargetFile"`
	Language           string             `json:"language"`
	Details            string             `json:"details"`
	MatchingIssues     []OssIssueData     `json:"matchingIssues"`
	Lesson             string             `json:"lesson,omitempty"`
	Remediation        string             `json:"remediation"`
	AppliedPolicyRules AppliedPolicyRules `json:"appliedPolicyRules,omitempty"`
}

func (o OssIssueData) GetKey() string {
	return o.Key
}

func (o OssIssueData) GetTitle() string {
	return o.Title
}

func (o OssIssueData) IsFixable() bool {
	return o.IsUpgradable &&
		o.IsPatchable &&
		len(o.UpgradePath) > 1 &&
		len(o.From) > 1 &&
		o.UpgradePath[1] != o.From[1]
}

func (o OssIssueData) GetFilterableIssueType() product.FilterableIssueType {
	return product.FilterableIssueTypeOpenSource
}

func (o OssIssueData) MarshalJSON() ([]byte, error) {
	type IssueAlias OssIssueData
	aliasStruct := struct {
		Type string `json:"type"`
		*IssueAlias
	}{
		Type:       "OssIssueData",
		IssueAlias: (*IssueAlias)(&o),
	}
	data, err := json.Marshal(aliasStruct)
	return data, err
}
