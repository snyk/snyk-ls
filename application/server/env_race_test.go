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

// TestSmokeEnvRace verifies that concurrent calls to smoke-test helpers that
// previously relied on os.Setenv do not race under -race.
//
// The API endpoint is now set via WithAPIEndpoint (per-server config option) so
// os.Setenv("SNYK_API") is never called from parallel tests. The log level is
// set via config.SetLogLevel which writes a zerolog global atomically and does
// not touch the process environment.
//
// This test therefore just exercises the new per-engine endpoint option in
// parallel goroutines and confirms there is no data race.
//
// Run as: go test -race ./application/server/... -run TestSmokeEnvRace -v
import (
	"sync"
	"testing"

	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestSmokeEnvRace(t *testing.T) {
	t.Parallel()
	const workers = 10
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			engine, tokenService := testutil.UnitTestWithEngine(t)
			// WithAPIEndpoint writes only to the per-engine config map — no
			// process-global os.Setenv, so no race under -race.
			_, _, _ = setupServer(t, engine, tokenService,
				WithAPIEndpoint("https://api.snyk.io"),
			)
		}()
	}
	wg.Wait()
}
