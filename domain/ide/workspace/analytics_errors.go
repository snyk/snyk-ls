/*
 * © 2026 Snyk Limited All rights reserved.
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

package workspace

import (
	"context"
	stderrors "errors"
	"strings"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"

	"github.com/snyk/snyk-ls/infrastructure/utils"
	"github.com/snyk/snyk-ls/internal/types"
)

// shouldEmitAnalytics centralizes the "do we record this scan on the
// 'Is Snyk OK?' dashboard?" policy. Checked at the call site so canceled and
// non-failing scans skip the goroutine entirely instead of spawning one that
// bails after categorization work.
func shouldEmitAnalytics(data *types.ScanData) bool {
	if data == nil || !data.SendAnalytics || data.Product == "" {
		return false
	}
	if data.Err != nil {
		if utils.IsNonFailingScanError(data.Err.Error()) {
			return false
		}
		if isCancellationError(data.Err) {
			return false
		}
	}
	return true
}

// isCancellationError reports whether err represents a routine cancellation
// (user abort, credential rotation, timeout). Routine cancellations are not
// scan failures and must not count on the "Is Snyk OK?" rollup.
func isCancellationError(err error) bool {
	return err != nil && (stderrors.Is(err, context.Canceled) || stderrors.Is(err, context.DeadlineExceeded))
}

// classifyError returns the analytics (category, code) pair for err, unwrapping
// the Snyk error catalog entry exactly once so the two values cannot drift.
//
// category is a low-cardinality product prefix (e.g. "SNYK-CLI") suitable for
// the default "Is Snyk OK?" dashboard rollup. code is the full catalog code
// (e.g. "SNYK-CLI-0008") for drill-down.
//
// For a nil error: ("", ""). For errors without a catalog entry:
// ("unknown", ""). Raw error.Error() text is never returned — only stable
// catalog identifiers — to keep analytics free of PII.
func classifyError(err error) (category, code string) {
	if err == nil {
		return "", ""
	}
	var snykErr snyk_errors.Error
	if !stderrors.As(err, &snykErr) || snykErr.ErrorCode == "" {
		return "unknown", ""
	}
	code = snykErr.ErrorCode
	parts := strings.SplitN(code, "-", 3)
	if len(parts) >= 2 && parts[0] != "" && parts[1] != "" {
		return parts[0] + "-" + parts[1], code
	}
	return code, code
}
