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

// categorizeError returns a low-cardinality product prefix derived from the
// Snyk error catalog code on err (e.g. "SNYK-CLI", "SNYK-OS"). For errors that
// do not carry a catalog entry it returns "unknown". For a nil error it
// returns the empty string.
//
// Why a prefix and not the full ErrorCode: ErrorCodes are ~hundreds across the
// catalog and would inflate analytics cardinality without adding signal to the
// default "Is Snyk OK?" dashboard rollup. The full code is emitted alongside
// via errorCode() for drill-downs.
func categorizeError(err error) string {
	if err == nil {
		return ""
	}
	var snykErr snyk_errors.Error
	if stderrors.As(err, &snykErr) && snykErr.ErrorCode != "" {
		parts := strings.SplitN(snykErr.ErrorCode, "-", 3)
		if len(parts) >= 2 {
			return parts[0] + "-" + parts[1]
		}
		return snykErr.ErrorCode
	}
	return "unknown"
}

// errorCode returns the full Snyk catalog ErrorCode (e.g. "SNYK-CLI-0008") for
// errors that wrap a catalog entry, or the empty string otherwise. It is
// emitted alongside categorizeError so dashboards can drill from prefix bucket
// (e.g. "SNYK-CLI") into the specific code.
//
// Raw error.Error() text is never returned — only stable catalog identifiers —
// to keep analytics free of file paths, repo URLs, and other PII.
func errorCode(err error) string {
	if err == nil {
		return ""
	}
	var snykErr snyk_errors.Error
	if stderrors.As(err, &snykErr) {
		return snykErr.ErrorCode
	}
	return ""
}
