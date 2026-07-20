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

// ---------------------------------------------------------------------------
// Item 1: FixFolder must bound the runner with an internal timeout
// ---------------------------------------------------------------------------

// TestFixFolder_AppliesInternalTimeout verifies that FixFolder wraps the work in
// a context with a deadline (p.opts.Timeout), mirroring Remediate. Without it a
// hung folder-wide fix run could stall the caller indefinitely. The caller here
// passes context.Background() (no deadline); after the fix the runner must
// observe a deadline on its context.
func TestFixFolder_AppliesInternalTimeout(t *testing.T) {
	repo := initGitRepo(t)
	commitFile(t, repo, "main.go", "package main\nvar x = 1\n")

	var hadDeadline bool
	runner := func(ctx context.Context, _ workflow.Engine, root, _ string) error {
		_, hadDeadline = ctx.Deadline()
		return os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nvar x = 2\n"), 0644)
	}

	p := remediation.NewRemyProvider(nil, runner)
	fr, ok := p.(remediation.FolderRemediator)
	require.True(t, ok)

	_, err := fr.FixFolder(context.Background(), types.FilePath(repo))
	require.NoError(t, err)
	assert.True(t, hadDeadline,
		"FixFolder must bound the runner with an internal timeout so a hung run cannot stall the caller")
}

// ---------------------------------------------------------------------------
// Item 2: per-ContentRoot mutex must not leak
// ---------------------------------------------------------------------------

// TestRemyProvider_RootMutexEvicted_NoLeak verifies that the per-root mutex is
// not retained forever. Before the fix, getOrCreateRootMu inserted a mutex per
// ContentRoot and never removed it, so rootMus grew unbounded. After the fix the
// mutex is evicted once no caller references it, so a completed Remediate leaves
// rootMus empty.
func TestRemyProvider_RootMutexEvicted_NoLeak(t *testing.T) {
	repo := initGitRepo(t)
	commitFile(t, repo, "main.go", "package main\nvar x = 1\n")

	runner := modifyRunner("main.go", "package main\nvar x = 2\n")
	p := remediation.NewRemyProvider(nil, runner)

	_, err := p.Remediate(context.Background(), remediation.RemediationRequest{
		FindingId:   "f1",
		ContentRoot: types.FilePath(repo),
		FilePath:    types.FilePath(filepath.Join(repo, "main.go")),
	})
	require.NoError(t, err)

	assert.Equal(t, 0, remediation.RootMuLen(p),
		"per-root mutex must be evicted after Remediate; rootMus must not grow unbounded")
}
