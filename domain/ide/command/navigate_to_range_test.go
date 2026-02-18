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
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
	"github.com/snyk/snyk-ls/internal/uri"
)

func TestNavigateToRange_SnykURI_DerivedFromPathToUri(t *testing.T) {
	testutil.UnitTest(t)

	filePath := filepath.Join(t.TempDir(), "main.go")

	// Derive the expected snyk:// URI from PathToUri — the production code
	// must use the same function, so the scheme swap is the only difference.
	fileUri := string(uri.PathToUri(types.FilePath(filePath)))
	expectedPrefix := strings.Replace(fileUri, "file://", "snyk://", 1)

	ctrl := gomock.NewController(t)
	mockSrv := mock_types.NewMockServer(ctrl)
	c := testutil.UnitTest(t)

	rangeArg := map[string]any{
		"start": map[string]any{"line": float64(5), "character": float64(0)},
		"end":   map[string]any{"line": float64(5), "character": float64(10)},
	}

	cmd := &navigateToRangeCommand{
		command: types.CommandData{
			Arguments: []any{filePath, rangeArg, "SNYK-JS-123", "oss"},
		},
		srv:    mockSrv,
		logger: c.Logger(),
		c:      c,
	}

	var capturedSnykURI string
	mockSrv.EXPECT().Callback(gomock.Any(), "window/showDocument", gomock.Any()).DoAndReturn(
		func(_ context.Context, _ string, params any) (any, error) {
			if p, ok := params.(types.ShowDocumentParams); ok && !p.TakeFocus {
				capturedSnykURI = string(p.Uri)
			}
			return nil, nil
		}).Times(2)

	_, err := cmd.Execute(context.Background())
	require.NoError(t, err)

	require.NotEmpty(t, capturedSnykURI, "detail panel callback should have been invoked")
	assert.True(t, strings.HasPrefix(capturedSnykURI, expectedPrefix),
		"snyk URI path must equal uri.PathToUri output with scheme swapped\n  got:  %s\n  want prefix: %s",
		capturedSnykURI, expectedPrefix)
	assert.Contains(t, capturedSnykURI, "product=oss")
	assert.Contains(t, capturedSnykURI, "issueId=SNYK-JS-123")
	assert.Contains(t, capturedSnykURI, "action=showInDetailPanel")
	assert.NotContains(t, capturedSnykURI, `\`,
		"URI must not contain backslashes on any platform")
}
