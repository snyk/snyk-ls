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
}

type IssueData struct {
	PublicId string `json:"publicId"`
	// DocumentationURL: Snyk security rule URL (e.g. https://snyk.io/security-rules/SNYK-CC-K8S-13)
	DocumentationURL string `json:"documentation"`
	LineNumber       int    `json:"lineNumber"`
	// IssueDescription: a short description of the issue (e.g. "The pod is sharing host's IPC namespace")
	IssueDescription string `json:"issue"`
	Impact           string `json:"impact"`
	// Remediation: a short description of how to fix the issue (e.g. "Remove `hostIPC` attribute, or set value to `false`")
	Remediation string `json:"resolve:omitempty"`
	// References: List of reference URLs
	References []string `json:"references:omitempty"`
}
