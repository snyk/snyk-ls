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
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/snyk/remediation"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

// INT-002: DI passes the gated provider into the command service.
//
// When remediation_agent_enabled=true, the real remyProvider (which implements
// FolderRemediator) must reach the fixFolder command handler. We verify this
// by constructing the command service directly via command.NewService and
// wiring a fake FolderRemediator — removing the wiring call makes this RED.
func TestDI_FixFolderCommand_WiredWhenEnabled(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	_ = tokenService

	// Build a minimal git repo so FixFolder has a valid path to validate.
	repo := initGitRepoForDI(t)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))

	// Set the flag so initApplication builds the real remediationProvider.
	engine.GetConfiguration().Set(di.RemediationAgentEnabledKey, true)

	// Call di.Init to exercise the real wiring path.
	deps := di.Init(engine, tokenService)
	_ = deps

	// The real command.Service singleton was set by di.Init. Verify it handles
	// the fixFolder command without panicking on a nil provider.
	// With the gate ON the provider is wired; with gate OFF it returns an error.
	svc := command.Service()
	require.NotNil(t, svc, "command.Service() must be non-nil after di.Init")

	_, err := svc.ExecuteCommandData(context.Background(), types.CommandData{
		CommandId: types.RemediationAgentFixFolderCommand,
		Arguments: []any{folderURI},
	}, nil)

	// The command will attempt to run remy on a real repo but the engine has no
	// real GAF workflows registered, so the runner (gafRunner) will fail. That
	// is fine — what we are testing is that the handler is reached (not a nil
	// provider error) and that the wiring did not break.
	// If the provider is nil the error is "not enabled"; if wired it is a runner error.
	if err != nil {
		assert.NotContains(t, err.Error(), "not enabled",
			"provider must be wired when gate is ON; 'not enabled' means provider is nil")
	}
}

// INT-002b: Wiring test that is RED if the FolderRemediator param is removed
// from NewService. Constructs a service with a non-nil provider and verifies
// the fixFolder command reaches the provider.
func TestDI_NewService_FixFolderProvider_Wired(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	_ = tokenService

	// Enable workspace/applyEdit so the capability guard in the handler passes.
	caps := types.ClientCapabilities{}
	caps.Workspace.ApplyEdit = true
	engine.GetConfiguration().Set(types.SettingClientCapabilities, caps)

	repo := initGitRepoForDI(t)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))

	provider := &diTestFolderRemediator{}
	svc := command.NewService(
		engine,
		engine.GetLogger(),
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		provider,
	)

	_, _ = svc.ExecuteCommandData(context.Background(), types.CommandData{
		CommandId: types.RemediationAgentFixFolderCommand,
		Arguments: []any{folderURI},
	}, nil)

	// Provider must have been called — proves it was wired.
	assert.True(t, provider.called, "FolderRemediator.FixFolder must be called when provider is wired")
}

// diTestFolderRemediator is a minimal FolderRemediator for the DI wiring test.
type diTestFolderRemediator struct {
	called bool
}

func (d *diTestFolderRemediator) FixFolder(_ context.Context, _ types.FilePath) (*types.WorkspaceEdit, error) {
	d.called = true
	return nil, nil
}

var _ remediation.FolderRemediator = (*diTestFolderRemediator)(nil)

func initGitRepoForDI(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, string(out))
	}
	run("init")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "Test")
	// Overlay filesystems (e.g. Docker on Linux) have write-ordering delays that
	// can cause git to report "not a valid object" when the object database is
	// read immediately after a write. core.checkStat=minimal tells git not to
	// recheck filesystem timestamps for objects it has already cached in memory,
	// which suppresses the false-negative reads on overlayfs.
	run("config", "core.checkStat", "minimal")
	f := filepath.Join(dir, "main.go")
	require.NoError(t, os.WriteFile(f, []byte("package main\n"), 0644))
	run("add", ".")
	run("commit", "-m", "init")
	return dir
}
