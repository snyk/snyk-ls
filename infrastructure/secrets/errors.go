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

package secrets

import (
	stderrors "errors"
	"fmt"

	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"

	"github.com/snyk/snyk-ls/internal/types"
)

// ignorableSecretsErrorCodes lists snyk_errors.Error ErrorCode values that indicate
// expected no-op conditions (e.g. the target file is excluded or unsupported).
// Scans that hit these codes return early without touching the issue cache so that
// previously discovered findings remain visible in the IDE.
//
// SNYK-CLI-0016 (FeatureNotEnabled) is intentionally excluded: it signals an
// org-level state change and should surface as a real error rather than silently
// clearing cached findings.
var ignorableSecretsErrorCodes = map[string]bool{ //nolint:gochecknoglobals // effectively a package-level constant — immutable after init
	"SNYK-CLI-0008": true, // NoSupportedFilesFound: file ignored or unsupported type
}

// isIgnorableError returns true when err is a snyk catalog error whose code is
// known to be non-critical (e.g. no files to scan because the target is ignored).
func isIgnorableError(err error) bool {
	var snykErr snyk_errors.Error
	return stderrors.As(err, &snykErr) && ignorableSecretsErrorCodes[snykErr.ErrorCode]
}

// handleSecretsInvokeError processes a non-nil error from engine.InvokeWithConfig.
// It returns (empty, nil) for ignorable conditions and (nil, wrappedErr) otherwise.
func handleSecretsInvokeError(err error, logger *zerolog.Logger) ([]types.Issue, error) {
	if isIgnorableError(err) {
		logger.Debug().Msg("Secrets scanner: file excluded or unsupported, returning no error")
		return []types.Issue{}, nil
	}
	return nil, fmt.Errorf("failed secrets scan: %w", err)
}
