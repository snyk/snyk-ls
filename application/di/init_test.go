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

package di_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/internal/testutil"
)

// TestDependencies_AllFieldsPopulated verifies that after TestInit the returned
// Dependencies struct has all service fields populated (not nil).  This is the
// TDD guard for the Step-1 expansion of the struct.
func TestDependencies_AllFieldsPopulated(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	deps := di.TestInit(t, engine, tokenService, nil)

	assert.NotNil(t, deps.AuthenticationService, "AuthenticationService must be set")
	assert.NotNil(t, deps.ConfigResolver, "ConfigResolver must be set")
	assert.NotNil(t, deps.FeatureFlagService, "FeatureFlagService must be set")
	assert.NotNil(t, deps.Notifier, "Notifier must be set")
	assert.NotNil(t, deps.LearnService, "LearnService must be set")
	assert.NotNil(t, deps.LdxSyncService, "LdxSyncService must be set")
	assert.NotNil(t, deps.ScanStateAggregator, "ScanStateAggregator must be set")

	// New fields added in Step 1
	assert.NotNil(t, deps.FileWatcher, "FileWatcher must be set")
	assert.NotNil(t, deps.ErrorReporter, "ErrorReporter must be set")
	assert.NotNil(t, deps.HoverService, "HoverService must be set")
	assert.NotNil(t, deps.Scanner, "Scanner must be set")
	assert.NotNil(t, deps.ScanPersister, "ScanPersister must be set")
	assert.NotNil(t, deps.ScanNotifier, "ScanNotifier must be set")
	assert.NotNil(t, deps.Installer, "Installer must be set")
	assert.NotNil(t, deps.CodeActionService, "CodeActionService must be set")
	assert.NotNil(t, deps.Initializer, "Initializer must be set")
}

// TestTestInit_ReturnedDepsAreIndependent verifies that two consecutive TestInit
// calls (even with different engines) return independent Dependencies structs.
// Specifically, the Notifier field of the first call must not be overwritten by
// the second call — i.e. TestInit must NOT write to di package-level globals.
func TestTestInit_ReturnedDepsAreIndependent(t *testing.T) {
	engine1, tokenService1 := testutil.UnitTestWithEngine(t)
	engine2, tokenService2 := testutil.UnitTestWithEngine(t)

	deps1 := di.TestInit(t, engine1, tokenService1, nil)
	deps2 := di.TestInit(t, engine2, tokenService2, nil)

	// Each call must return its own Notifier instance.
	// If TestInit still writes to the package-level notifier var, the second
	// call overwrites it and deps1.Notifier == deps2.Notifier (same pointer).
	assert.NotSame(t, deps1.Notifier, deps2.Notifier,
		"each TestInit call must return an independent Notifier, not a shared global")
	assert.NotSame(t, deps1.HoverService, deps2.HoverService,
		"each TestInit call must return an independent HoverService, not a shared global")
	assert.NotSame(t, deps1.ErrorReporter, deps2.ErrorReporter,
		"each TestInit call must return an independent ErrorReporter, not a shared global")
}
