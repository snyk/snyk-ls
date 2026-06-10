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

package server

import (
	"os"
	"sync"
)

// snykAPIEnvOnce ensures SNYK_API is written at most once across all parallel
// smoke tests. Every caller passes the same value (the env-var or the fallback
// constant "https://api.snyk.io"), so a single write is correct and avoids the
// concurrent-write data race detected by -race.
//
//nolint:gochecknoglobals // package-level once is the canonical Go pattern for
// idempotent one-time side effects in parallel tests.
var snykAPIEnvOnce sync.Once

// logLevelEnvOnce ensures SNYK_LOG_LEVEL is written at most once across all
// parallel tests. The value is constant for the process lifetime, so a
// per-test restore via Cleanup is unnecessary and itself a racing write.
//
//nolint:gochecknoglobals
var logLevelEnvOnce sync.Once

// setSmokeAPIEndpoint sets SNYK_API to endpoint exactly once for the process.
// Concurrent callers block until the first write completes, then return.
// Safe to call from parallel tests.
func setSmokeAPIEndpoint(endpoint string) {
	snykAPIEnvOnce.Do(func() {
		_ = os.Setenv("SNYK_API", endpoint) //nolint:usetesting // called from parallel tests; t.Setenv panics
	})
}

// setSmokeLogLevel sets SNYK_LOG_LEVEL to level exactly once for the process.
// Safe to call from parallel tests.
func setSmokeLogLevel(level string) {
	logLevelEnvOnce.Do(func() {
		_ = os.Setenv("SNYK_LOG_LEVEL", level) //nolint:usetesting // called from parallel tests; t.Setenv panics
	})
}
