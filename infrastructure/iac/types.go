/*
 * © 2022 Snyk Limited All rights reserved.
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

package iac

import (
	"github.com/snyk/snyk-ls/application/server/lsp"
)

type iacScanResult struct {
	TargetFile string     `json:"targetFile"`
	IacIssues  []iacIssue `json:"infrastructureAsCodeIssues"`
	ErrorCode  int        `json:"code"`
}

type iacDescription struct {
	Issue   string `json:"issue"`
	Impact  string `json:"impact"`
	Resolve string `json:"resolve"`
}

type iacIssue struct {
	PublicID       string         `json:"publicId"`
	Title          string         `json:"title"`
	Severity       string         `json:"severity"`
	LineNumber     int            `json:"lineNumber"`
	Documentation  lsp.Uri        `json:"documentation"`
	IacDescription iacDescription `json:"iacDescription"`
	Path           []string       `json:"path"`
	References     []string       `json:"references"`
}

type IacIssueData struct {
	// PublicID: unique identifier for the issue; it is the same as the ScanIssue.ID
	PublicId string `json:"publicId"`
	// Documentation is a URL which is constructed from the PublicID (e.g. https://snyk.io/security-rules/SNYK-CC-K8S-13)
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
	References []string `json:"references:omitempty"`
}
