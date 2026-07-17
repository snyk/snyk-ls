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

package remediation_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk/remediation"
	"github.com/snyk/snyk-ls/internal/types"
)

// TestFixFolder_DirtyWorktree_ReturnsError verifies that FixFolder rejects a
// worktree that has uncommitted modifications to tracked files.  The guard
// runs git status --porcelain --untracked-files=no; any non-empty output
// causes an error containing "has uncommitted changes".  Inverting the guard
// condition (status != "" → status == "") would make a dirty worktree pass
// and this test would fail because the error would no longer be returned.
func TestFixFolder_DirtyWorktree_ReturnsError(t *testing.T) {
	repo := initGitRepo(t)
	commitFile(t, repo, "main.go", "package main\nvar x = 1\n")

	// Modify the tracked file without staging/committing it.
	require.NoError(t, os.WriteFile(filepath.Join(repo, "main.go"), []byte("package main\nvar x = 2\n"), 0o644))

	var runnerCalled bool
	trackingRunner := func(_ context.Context, _ workflow.Engine, _, _ string) error {
		runnerCalled = true
		return nil
	}

	p := remediation.NewRemyProvider(nil, trackingRunner)
	edit, err := p.FixFolder(context.Background(), types.FilePath(repo))
	require.ErrorContains(t, err, "has uncommitted changes")
	assert.Nil(t, edit)
	assert.False(t, runnerCalled, "runner must NOT be called when the dirty-worktree guard fires")
}

// TestFixFolder_AppliesInternalTimeout verifies that FixFolder wraps the runner
// with a context deadline (p.opts.Timeout). The caller passes context.Background()
// (no deadline); the runner must observe a deadline on its context.
func TestFixFolder_AppliesInternalTimeout(t *testing.T) {
	repo := initGitRepo(t)
	commitFile(t, repo, "main.go", "package main\nvar x = 1\n")

	var hadDeadline bool
	runner := func(ctx context.Context, _ workflow.Engine, root, _ string) error {
		_, hadDeadline = ctx.Deadline()
		return os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nvar x = 2\n"), 0644)
	}

	p := remediation.NewRemyProvider(nil, runner)
	_, err := p.FixFolder(context.Background(), types.FilePath(repo))
	require.NoError(t, err)
	assert.True(t, hadDeadline,
		"FixFolder must bound the runner with an internal timeout so a hung run cannot stall the caller")
}
