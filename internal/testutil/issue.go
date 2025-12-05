/*
 * © 2025 Snyk Limited
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

// Package testutil implements test setup functionality
package testutil

import (
	"github.com/google/uuid"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

// NewMockIssue creates a mock issue with default values for testing.
// The issue has ProductOpenSource, Medium severity, and a generated key.
func NewMockIssue(id string, path types.FilePath) *snyk.Issue {
	return &snyk.Issue{
		ID:               id,
		AffectedFilePath: path,
		Product:          product.ProductOpenSource,
		Severity:         types.Medium,
		AdditionalData:   snyk.OssIssueData{Key: util.Result(uuid.NewUUID()).String()},
	}
}

// NewMockIssueWithSeverity creates a mock issue with a specific severity.
func NewMockIssueWithSeverity(id string, path types.FilePath, severity types.Severity) *snyk.Issue {
	issue := NewMockIssue(id, path)
	issue.Severity = severity
	return issue
}

// NewMockIssueWithIgnored creates a mock issue with a specific ignored status.
func NewMockIssueWithIgnored(id string, path types.FilePath, ignored bool) *snyk.Issue {
	issue := NewMockIssue(id, path)
	issue.IsIgnored = ignored
	return issue
}
