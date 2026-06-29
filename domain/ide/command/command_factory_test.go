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

package command_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/snyk/remediation"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// INT-001: CreateFromCommandData wires provider and notifier into the handler.
// Deleting the wiring in CreateFromCommandData makes this test RED.
func TestCreateFromCommandData_FixFolder_WiresProviderAndNotifier(t *testing.T) {
	engine, _ := testutil.UnitTestWithEngine(t)
	// Enable the workspace/applyEdit capability so the guard passes.
	conf := engine.GetConfiguration()
	caps := types.ClientCapabilities{}
	caps.Workspace.ApplyEdit = true
	conf.Set(types.SettingClientCapabilities, caps)

	notifier := &fakeNotifier{}
	provider := &fakeFolderRemediator{}

	cmd, err := command.CreateFromCommandData(
		context.Background(),
		engine,
		types.CommandData{CommandId: types.RemediationAgentFixFolderCommand, Arguments: []any{"file:///tmp"}},
		nil, // srv
		nil, // authService
		nil, // featureFlagService
		nil, // learnService
		notifier,
		nil, // issueProvider
		nil, // codeScanner
		nil, // cli
		nil, // ldxSyncService
		nil, // configResolver
		nil, // scanStateFunc
		provider,
	)
	require.NoError(t, err)
	require.NotNil(t, cmd)

	// Execute the command with the folder path pointing to /tmp which exists.
	// The provider returns nil (no changes) — we only care that the handler
	// got a non-nil provider and notifier so no nil-pointer panic occurs.
	_, execErr := cmd.Execute(context.Background())
	// /tmp exists and is a dir; provider is non-nil; returns nil (no changes).
	assert.NoError(t, execErr, "provider and notifier must be wired; no nil-pointer panic")
}

// fakeFolderRemediatorForFactory satisfies remediation.FolderRemediator for factory tests.
// Using the same fakeFolderRemediator defined in remediation_fix_folder_test.go — but that
// is in the same test package so it is accessible.
var _ remediation.FolderRemediator = (*fakeFolderRemediator)(nil)
