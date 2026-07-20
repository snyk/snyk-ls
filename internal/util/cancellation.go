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

package util

import (
	"context"
	"errors"
)

// IsCancellation reports whether err represents an expected context cancellation
// rather than a genuine failure. Such errors occur when an operation is deliberately
// aborted — for example when the IDE cancels an in-flight snyk.login via an LSP
// $/cancelRequest while the user switches auth method, retries Authenticate, or logs
// out. Cancellations should be treated as a non-error: logged at debug level, not
// reported to Sentry, and not surfaced to the user.
//
// context.DeadlineExceeded is deliberately excluded: a deadline firing is a genuine
// timeout, which must stay visible to the user and to telemetry.
func IsCancellation(err error) bool {
	return errors.Is(err, context.Canceled)
}
