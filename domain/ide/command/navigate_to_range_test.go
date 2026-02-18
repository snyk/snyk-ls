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
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

func TestNavigateToRange_SnykURI_NormalizesBackslashes(t *testing.T) {
	testutil.UnitTest(t)
	ctrl := gomock.NewController(t)

	mockSrv := mock_types.NewMockServer(ctrl)
	c := testutil.UnitTest(t)
	logger := c.Logger()

	windowsPath := `C:\Users\dev\project\main.go`
	rangeArg := map[string]any{
		"start": map[string]any{"line": float64(0), "character": float64(0)},
		"end":   map[string]any{"line": float64(0), "character": float64(0)},
	}

	cmd := &navigateToRangeCommand{
		command: types.CommandData{
			Arguments: []any{windowsPath, rangeArg, "test-issue-id", "code"},
		},
		srv:    mockSrv,
		logger: logger,
		c:      c,
	}

	var capturedSnykURI string
	mockSrv.EXPECT().Callback(gomock.Any(), "window/showDocument", gomock.Any()).DoAndReturn(
		func(_ context.Context, _ string, params any) (any, error) {
			if p, ok := params.(types.ShowDocumentParams); ok {
				if !p.TakeFocus {
					capturedSnykURI = string(p.Uri)
				}
			}
			return nil, nil
		}).Times(2)

	_, err := cmd.Execute(context.Background())
	require.NoError(t, err)
	assert.Contains(t, capturedSnykURI, "snyk:")
	assert.NotContains(t, capturedSnykURI, `\`, "snyk:// URI must not contain backslashes")
	assert.Contains(t, capturedSnykURI, "C:/Users/dev/project/main.go")
}
