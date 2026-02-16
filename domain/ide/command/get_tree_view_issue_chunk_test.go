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

package command

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestGetTreeViewIssueChunk_Execute_WithMissingParams_ReturnsError(t *testing.T) {
	c := testutil.UnitTest(t)
	cmd := &getTreeViewIssueChunk{
		command: types.CommandData{CommandId: types.GetTreeViewIssueChunk},
		c:       c,
	}

	_, err := cmd.Execute(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing getTreeViewIssueChunk arguments")
}

func TestGetTreeViewIssueChunk_Execute_ReturnsChunkResultShape(t *testing.T) {
	c := testutil.UnitTest(t)
	cmd := &getTreeViewIssueChunk{
		command: types.CommandData{
			CommandId: types.GetTreeViewIssueChunk,
			Arguments: []any{
				map[string]any{
					"filePath": "/project/main.go",
					"product":  "Snyk Open Source",
					"range": map[string]any{
						"start": 0,
						"end":   100,
					},
				},
			},
		},
		c: c,
	}

	result, err := cmd.Execute(t.Context())
	require.NoError(t, err)

	chunkResult, ok := result.(types.GetTreeViewIssueChunkResult)
	require.True(t, ok, "result should be a GetTreeViewIssueChunkResult")
	assert.GreaterOrEqual(t, chunkResult.TotalFileIssues, 0)
	assert.GreaterOrEqual(t, chunkResult.NextStart, 0)
}

func TestParseGetTreeViewIssueChunkParams_RequiresFilePathAndProduct(t *testing.T) {
	_, err := parseGetTreeViewIssueChunkParams([]any{
		map[string]any{
			"range": map[string]any{"start": 0, "end": 10},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "filePath is required")

	_, err = parseGetTreeViewIssueChunkParams([]any{
		map[string]any{
			"filePath": "/project/main.go",
			"range":    map[string]any{"start": 0, "end": 10},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "product is required")
}
