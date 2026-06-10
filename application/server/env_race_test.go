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

// TestSmokeEnvRace verifies that the package-level once-guards (snykAPIEnvOnce,
// logLevelEnvOnce) prevent concurrent os.Setenv calls from racing.
//
// The test calls setSmokeAPIEndpoint and setSmokeLogLevel concurrently in
// multiple goroutines and runs with -race; any concurrent os.Setenv without the
// sync.Once guard would be flagged immediately by the race detector.
//
// Run as: go test -race ./application/server/... -run TestSmokeEnvRace -v
import (
	"sync"
	"testing"
)

func TestSmokeEnvRace(t *testing.T) {
	t.Parallel()
	const workers = 10
	var wg sync.WaitGroup
	wg.Add(workers * 2)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			setSmokeAPIEndpoint("https://api.snyk.io")
		}()
		go func() {
			defer wg.Done()
			setSmokeLogLevel("info")
		}()
	}
	wg.Wait()
}
