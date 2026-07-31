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

package types_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/types"
)

// INT-103: the JSON keys the daemon parses must be exactly as specified.
// Renaming a struct field or its json tag without coordinating with the
// daemon consumer breaks the cross-language contract silently at compile
// time. This test makes the break loud at test time.
func TestFolderFixResult_JSONContract(t *testing.T) {
	result := types.FolderFixResult{
		Files: []types.FolderFixFileResult{
			{
				WorkspacePath: "/tmp/repo/main.go",
				WorktreePath:  "/tmp/repo/main.go",
				Diff:          "--- a/main.go\n+++ b/main.go\n@@ -1,2 +1,2 @@\n package main\n-var x = 1\n+var x = 2\n",
			},
		},
	}

	b, err := json.Marshal(result)
	require.NoError(t, err)

	// Top-level key must be "files".
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(b, &raw))
	assert.Contains(t, raw, "files", "top-level key must be 'files'")

	// File-entry keys must be exactly workspacePath, worktreePath, diff.
	var files []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw["files"], &files))
	require.Len(t, files, 1)
	assert.Contains(t, files[0], "workspacePath", "file entry must have 'workspacePath' key")
	assert.Contains(t, files[0], "worktreePath", "file entry must have 'worktreePath' key")
	assert.Contains(t, files[0], "diff", "file entry must have 'diff' key")
	assert.Len(t, files[0], 3, "file entry must have exactly 3 keys")
}

// TestFolderFixResult_EmptyFiles_MarshalAsArray verifies that an empty Files
// slice marshals as [] not null. The daemon always parses a single shape.
func TestFolderFixResult_EmptyFiles_MarshalAsArray(t *testing.T) {
	result := types.FolderFixResult{Files: []types.FolderFixFileResult{}}
	b, err := json.Marshal(result)
	require.NoError(t, err)
	assert.True(t, strings.Contains(string(b), `"files":[]`),
		"empty Files must marshal as [] not null, got: %s", string(b))
}

// TestFolderFixFileResult_DeletionEntry_JSONContract guards against an accidental
// omitempty on the worktreePath json tag that would silently break the daemon's
// deletion detection. A deletion entry with WorktreePath=="" must round-trip as
// "worktreePath":"" — not as a missing key, which omitempty would produce.
func TestFolderFixFileResult_DeletionEntry_JSONContract(t *testing.T) {
	entry := types.FolderFixFileResult{
		WorkspacePath: "/workspace/repo/todelete.go",
		WorktreePath:  "", // empty string signals deletion to the daemon
		Diff:          "--- a/todelete.go\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-package main\n-var x = 1\n",
	}

	b, err := json.Marshal(entry)
	require.NoError(t, err)

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(b, &raw))

	// "worktreePath" must be present in the JSON object with value "" — not absent.
	// If the tag had omitempty, an empty string would be silently dropped, and the
	// daemon would be unable to distinguish a deletion from a missing field.
	rawVal, present := raw["worktreePath"]
	require.True(t, present,
		"worktreePath key must always be present in JSON output, even when the value is an empty string; "+
			"omitempty on this tag would silently break the daemon's deletion detection")
	assert.Equal(t, `""`, string(rawVal),
		"deletion entry's worktreePath must serialize as empty string \"\", not as a missing key")
}
