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
	"encoding/json"
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
	assert.Contains(t, err.Error(), "expected 5 arguments")
}

func TestGetTreeViewIssueChunk_Execute_FlatArgs_ReturnsChunkResultWithRequestId(t *testing.T) {
	c := testutil.UnitTest(t)
	cmd := &getTreeViewIssueChunk{
		command: types.CommandData{
			CommandId: types.GetTreeViewIssueChunk,
			Arguments: []any{"req-123", "/project/main.go", "Snyk Open Source", float64(0), float64(100)},
		},
		c: c,
	}

	result, err := cmd.Execute(t.Context())
	require.NoError(t, err)

	chunkResult, ok := result.(types.GetTreeViewIssueChunkResult)
	require.True(t, ok, "result should be a GetTreeViewIssueChunkResult")
	assert.Equal(t, "req-123", chunkResult.RequestId)
	assert.GreaterOrEqual(t, chunkResult.TotalFileIssues, 0)
	assert.GreaterOrEqual(t, chunkResult.NextStart, 0)
}

func TestParseGetTreeViewIssueChunkParams_FlatArgs(t *testing.T) {
	params, err := parseGetTreeViewIssueChunkParams([]any{
		"req-abc", "/project/main.go", "Snyk Code", float64(5), float64(15),
	})
	require.NoError(t, err)
	assert.Equal(t, "req-abc", params.RequestId)
	assert.Equal(t, "/project/main.go", params.FilePath)
	assert.Equal(t, "Snyk Code", params.Product)
	assert.Equal(t, 5, params.Range.Start)
	assert.Equal(t, 15, params.Range.End)
}

func TestParseGetTreeViewIssueChunkParams_MissingFilePath(t *testing.T) {
	_, err := parseGetTreeViewIssueChunkParams([]any{"req-1", "", "Snyk Code", float64(0), float64(10)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "filePath is required")
}

func TestParseGetTreeViewIssueChunkParams_MissingProduct(t *testing.T) {
	_, err := parseGetTreeViewIssueChunkParams([]any{"req-1", "/main.go", "", float64(0), float64(10)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "product is required")
}

func TestParseGetTreeViewIssueChunkParams_TooFewArgs(t *testing.T) {
	_, err := parseGetTreeViewIssueChunkParams([]any{"req-1", "/main.go"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected 5 arguments")
}

func TestToInt_ParsesStringNumbers(t *testing.T) {
	assert.Equal(t, 42, toInt("42"))
	assert.Equal(t, 7, toInt(" 7 "))
	assert.Equal(t, 0, toInt("not-a-number"))
}

func TestToInt_ParsesJSONNumber(t *testing.T) {
	assert.Equal(t, 13, toInt(json.Number("13")))
}
