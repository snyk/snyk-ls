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

// Package remediation defines the interface for autonomous finding remediation.
package remediation

import (
	"context"

	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

// RemediationRequest describes the finding for which a fix is requested.
type RemediationRequest struct {
	FindingId   string
	FilePath    types.FilePath
	ContentRoot types.FilePath
	Range       types.Range
	Product     product.Product
}

// RemediationProvider computes an autonomous fix for a single finding.
// Returns nil when no fix can be computed; callers treat nil as "no fix available".
type RemediationProvider interface {
	Remediate(ctx context.Context, req RemediationRequest) (*types.WorkspaceEdit, error)
}
