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

func Test_categorizeError_NilError(t *testing.T) {
	assert.Equal(t, "", categorizeError(nil))
}

func Test_categorizeError_NonCatalogError(t *testing.T) {
	assert.Equal(t, "unknown", categorizeError(stderrors.New("boom")))
}

func Test_categorizeError_CatalogError_SnykCliPrefix(t *testing.T) {
	err := snyk_errors.Error{ErrorCode: "SNYK-CLI-0008", Title: "NoSupportedFilesFound"}
	assert.Equal(t, "SNYK-CLI", categorizeError(err))
}

func Test_categorizeError_CatalogError_SnykOsPrefix(t *testing.T) {
	err := snyk_errors.Error{ErrorCode: "SNYK-OS-7001", Title: "Request timeout"}
	assert.Equal(t, "SNYK-OS", categorizeError(err))
}

func Test_categorizeError_CatalogError_MalformedCode(t *testing.T) {
	// Codes without a "-" separator fall back to the full code string so
	// the dashboard still gets a usable bucket name.
	err := snyk_errors.Error{ErrorCode: "SHORT", Title: "Malformed"}
	assert.Equal(t, "SHORT", categorizeError(err))
}

func Test_categorizeError_WrappedCatalogError(t *testing.T) {
	// errors.As must unwrap to find the catalog error.
	inner := snyk_errors.Error{ErrorCode: "SNYK-CLI-0008"}
	wrapped := fmt.Errorf("scan failed: %w", inner)
	assert.Equal(t, "SNYK-CLI", categorizeError(wrapped))
}

func Test_errorCode_NilError(t *testing.T) {
	assert.Equal(t, "", errorCode(nil))
}

func Test_errorCode_NonCatalogError(t *testing.T) {
	assert.Equal(t, "", errorCode(stderrors.New("boom")))
}

func Test_errorCode_CatalogError(t *testing.T) {
	err := snyk_errors.Error{ErrorCode: "SNYK-CLI-0008", Title: "NoSupportedFilesFound"}
	assert.Equal(t, "SNYK-CLI-0008", errorCode(err))
}

func Test_errorCode_WrappedCatalogError(t *testing.T) {
	inner := snyk_errors.Error{ErrorCode: "SNYK-OS-7001"}
	wrapped := fmt.Errorf("upstream failure: %w", inner)
	assert.Equal(t, "SNYK-OS-7001", errorCode(wrapped))
}
