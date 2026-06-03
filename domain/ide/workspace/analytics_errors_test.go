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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

func Test_classifyError_NilError(t *testing.T) {
	cat, code := classifyError(nil)
	assert.Equal(t, "", cat)
	assert.Equal(t, "", code)
}

func Test_classifyError_NonCatalogError(t *testing.T) {
	cat, code := classifyError(stderrors.New("boom"))
	assert.Equal(t, "unknown", cat)
	assert.Equal(t, "", code)
}

func Test_classifyError_CatalogError_SnykCliPrefix(t *testing.T) {
	cat, code := classifyError(snyk_errors.Error{ErrorCode: "SNYK-CLI-0008", Title: "NoSupportedFilesFound"})
	assert.Equal(t, "SNYK-CLI", cat)
	assert.Equal(t, "SNYK-CLI-0008", code)
}

func Test_classifyError_CatalogError_SnykOsPrefix(t *testing.T) {
	cat, code := classifyError(snyk_errors.Error{ErrorCode: "SNYK-OS-7001", Title: "Request timeout"})
	assert.Equal(t, "SNYK-OS", cat)
	assert.Equal(t, "SNYK-OS-7001", code)
}

func Test_classifyError_CatalogError_MalformedNoSeparator(t *testing.T) {
	// Codes without a "-" separator fall back to the full code string so the
	// dashboard still gets a usable bucket name and the drill-down code matches.
	cat, code := classifyError(snyk_errors.Error{ErrorCode: "SHORT", Title: "Malformed"})
	assert.Equal(t, "SHORT", cat)
	assert.Equal(t, "SHORT", code)
}

func Test_classifyError_CatalogError_TrailingDashIsHardened(t *testing.T) {
	// "SNYK-" used to produce category "SNYK-" because SplitN admits an empty
	// second part. Fall back to the full code so analytics bucket names never
	// end with a dangling separator.
	cat, code := classifyError(snyk_errors.Error{ErrorCode: "SNYK-", Title: "Malformed"})
	assert.Equal(t, "SNYK-", cat, "category falls back to the full code when split parts are empty")
	assert.Equal(t, "SNYK-", code)
}

func Test_classifyError_WrappedCatalogError(t *testing.T) {
	// errors.As must unwrap to find the catalog error.
	inner := snyk_errors.Error{ErrorCode: "SNYK-CLI-0008"}
	wrapped := fmt.Errorf("scan failed: %w", inner)
	cat, code := classifyError(wrapped)
	assert.Equal(t, "SNYK-CLI", cat)
	assert.Equal(t, "SNYK-CLI-0008", code)
}

func Test_classifyError_CatalogError_EmptyErrorCode(t *testing.T) {
	// snyk_errors.Error wrapper with no ErrorCode should still classify as
	// "unknown" rather than emitting an empty category.
	cat, code := classifyError(snyk_errors.Error{Title: "no code"})
	assert.Equal(t, "unknown", cat)
	assert.Equal(t, "", code)
}
