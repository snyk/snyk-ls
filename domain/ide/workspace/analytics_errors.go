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
	stderrors "errors"
	"strings"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

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
