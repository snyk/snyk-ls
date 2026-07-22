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
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

// INT-101: CreateFromCommandData wires provider into the handler.
// Deleting the wiring in CreateFromCommandData (the case for
// RemediationAgentFixFolderCommand) makes this test RED.
func TestCreateFromCommandData_FixFolder_WiresProvider(t *testing.T) {
	engine, _ := testutil.UnitTestWithEngine(t)

	notifier := noti.NewMockNotifier()
	provider := &fakeFolderRemediator{}

	folderURI := string(uri.PathToUri(types.FilePath(t.TempDir())))

	cmd, err := command.CreateFromCommandData(
		context.Background(),
		engine,
		types.CommandData{CommandId: types.RemediationAgentFixFolderCommand, Arguments: []any{folderURI}},
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

	// Execute the command with a real temp dir that exists on all OSes.
	// The provider returns empty results — we only care that the handler
	// got a non-nil provider so no nil-pointer panic occurs.
	_, execErr := cmd.Execute(context.Background())
	assert.NoError(t, execErr, "provider must be wired; no nil-pointer panic")
}

// fakeFolderRemediatorForFactory satisfies remediation.FolderRemediator for factory tests.
// Using the same fakeFolderRemediator defined in remediation_fix_folder_test.go — but that
// is in the same test package so it is accessible.
var _ remediation.FolderRemediator = (*fakeFolderRemediator)(nil)
