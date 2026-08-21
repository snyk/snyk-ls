/*
 * © 2022-2026 Snyk Limited
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
	"testing"

	"github.com/cucumber/godog"
)

// TestBDD runs every Gherkin scenario under features/ against the real
// language server started via the existing test harness (setupServer,
// testsupport.JsonRPCRecorder). It lives in package server, not a separate
// test/acceptance package, precisely so its step definitions
// (bdd_steps_test.go) can reuse that unexported harness instead of building
// a second, divergent one.
//
// Options.TestingT is intentionally NOT set: bddSteps.beforeScenario/
// afterScenario already run every scenario as its own t.Run subtest of t, so
// that setupServer's t.Cleanup fires per scenario. Also setting TestingT
// would make godog wrap the same scenario in a second, colliding subtest.
func TestBDD(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: func(sc *godog.ScenarioContext) {
			newBDDSteps(t).register(sc)
		},
		Options: &godog.Options{
			Format: "pretty",
			Paths:  []string{"../../features"},
			Strict: true,
		},
	}

	if suite.Run() != 0 {
		t.Fatal("BDD feature suite failed")
	}
}
