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
	"testing"

	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk/remediation"
)

// noopRunner is a fake remyRunner that makes no file changes.
func noopRunner(_ context.Context, _ workflow.Engine, _, _ string) error {
	return nil
}

func TestNewRemyProvider_ReturnsProvider(t *testing.T) {
	p := remediation.NewRemyProvider(nil, noopRunner)
	assert.NotNil(t, p)
}

// TestWorkspaceEditFromContent_SimpleEdit verifies that a basic single-hunk
// unified diff produces the expected TextEdit.
func TestWorkspaceEditFromContent_SimpleEdit(t *testing.T) {
	original := []byte("line1\nline2\nline3\n")
	diff := "--- a/file.go\n+++ b/file.go\n@@ -2,1 +2,1 @@\n-line2\n+LINE2\n"
	edit, err := remediation.ExportedWorkspaceEditFromContent("/tmp/file.go", original, diff)
	require.NoError(t, err)
	require.NotNil(t, edit)
	edits := edit.Changes["/tmp/file.go"]
	require.NotEmpty(t, edits)
}

func TestWorkspaceEditFromContent_EmptyOriginal(t *testing.T) {
	edit, err := remediation.ExportedWorkspaceEditFromContent("/tmp/file.go", []byte{}, "some diff")
	require.Error(t, err)
	assert.Nil(t, edit)
}

func TestWorkspaceEditFromContent_EmptyDiffString(t *testing.T) {
	edit, err := remediation.ExportedWorkspaceEditFromContent("/tmp/file.go", []byte("content\n"), "")
	require.Error(t, err)
	assert.Nil(t, edit)
}

func TestWorkspaceEditFromContent_MalformedHunk(t *testing.T) {
	diff := "@@ bad hunk header\n-old\n+new\n"
	edit, err := remediation.ExportedWorkspaceEditFromContent("/tmp/file.go", []byte("old\n"), diff)
	require.Error(t, err)
	assert.Nil(t, edit)
}

func TestWorkspaceEditFromContent_NoNewlineAtEndAfterInsertion(t *testing.T) {
	original := []byte("old\n")
	diff := "--- a/file.go\n+++ b/file.go\n@@ -1,1 +1,1 @@\n-old\n+new\n\\ No newline at end of file\n"
	edit, err := remediation.ExportedWorkspaceEditFromContent("/tmp/file.go", original, diff)
	require.NoError(t, err)
	require.NotNil(t, edit)
	edits := edit.Changes["/tmp/file.go"]
	require.NotEmpty(t, edits)
	for _, e := range edits {
		if e.NewText != "" {
			assert.False(t, len(e.NewText) > 0 && e.NewText[len(e.NewText)-1] == '\n',
				"insertion before '\\No newline' must not end with newline")
		}
	}
}

func TestWorkspaceEditFromContent_NoNewlineAtEndAfterDeletion(t *testing.T) {
	original := []byte("old")
	diff := "--- a/file.go\n+++ b/file.go\n@@ -1,1 +1,1 @@\n-old\n\\ No newline at end of file\n+new\n"
	_, err := remediation.ExportedWorkspaceEditFromContent("/tmp/file.go", original, diff)
	_ = err // no panic is the invariant
}

func TestWorkspaceEditFromContent_ConsecutiveInsertions(t *testing.T) {
	original := []byte("line1\nline2\n")
	diff := "--- a/file.go\n+++ b/file.go\n@@ -1,2 +1,4 @@\n line1\n+inserted1\n+inserted2\n line2\n"
	edit, err := remediation.ExportedWorkspaceEditFromContent("/tmp/file.go", original, diff)
	require.NoError(t, err)
	require.NotNil(t, edit)
	edits := edit.Changes["/tmp/file.go"]
	require.NotEmpty(t, edits)
	found := false
	for _, e := range edits {
		if e.NewText != "" {
			found = true
		}
	}
	assert.True(t, found, "expected at least one insertion TextEdit")
}

func TestWorkspaceEditFromContent_NoDiffHunks_ReturnsNil(t *testing.T) {
	diff := "--- a/file.go\n+++ b/file.go\n"
	edit, err := remediation.ExportedWorkspaceEditFromContent("/tmp/file.go", []byte("line1\n"), diff)
	require.NoError(t, err)
	assert.Nil(t, edit)
}

func TestWorkspaceEditFromContent_MakeLineEdit_NegativeLine(t *testing.T) {
	diff := "--- a/file.go\n+++ b/file.go\n@@ -0,0 +0,1 @@\n+new\n"
	original := []byte("existing\n")
	_, err := remediation.ExportedWorkspaceEditFromContent("/tmp/file.go", original, diff)
	_ = err // no panic is the invariant
}
