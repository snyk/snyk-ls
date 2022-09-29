/*
 * Copyright 2022 Snyk Ltd.
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
