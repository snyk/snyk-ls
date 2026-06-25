/*
 * © 2023 Snyk Limited
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

package server

import (
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/mock_snyk"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

func Test_textDocumentInlineValues_shouldBeServed(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, _, _ := setupServer(t, engine, tokenService)

	rsp, err := loc.Client.Call(t.Context(), "textDocument/inlineValue", nil)
	assert.NoError(t, err)

	var result []types.InlineValue
	err = rsp.UnmarshalResult(&result)
	assert.NoError(t, err)
}

func Test_textDocumentInlineValues_InlineValues(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)

	dir, err := filepath.Abs("testdata")
	require.NoError(t, err)
	testFilePath := types.FilePath(filepath.Join(dir, "package.json"))
	documentURI := uri.PathToUri(testFilePath)

	inlineRange := types.Range{Start: types.Position{Line: 17}, End: types.Position{Line: 17}}

	mockValue := mock_snyk.NewMockInlineValue(ctrl)
	mockValue.EXPECT().Range().Return(inlineRange).AnyTimes()
	mockValue.EXPECT().Text().Return("Issues: 1").AnyTimes()

	mockProvider := mock_snyk.NewMockInlineValueProvider(ctrl)
	mockProvider.EXPECT().GetInlineValues(testFilePath, gomock.Any()).Return([]snyk.InlineValue{mockValue}, nil)

	loc, _, _ := setupServer(t, engine, tokenService,
		WithDeps(di.Dependencies{
			InlineValueProvider: mockProvider,
		}))

	rsp, err := loc.Client.Call(t.Context(), "textDocument/inlineValue", types.InlineValueParams{
		TextDocument: sglsp.TextDocumentIdentifier{URI: documentURI},
		Range:        sglsp.Range{Start: sglsp.Position{Line: 17}, End: sglsp.Position{Line: 17}},
	})
	require.NoError(t, err)

	var inlineValues []types.InlineValue
	require.NoError(t, rsp.UnmarshalResult(&inlineValues))
	require.Len(t, inlineValues, 1)
	assert.Equal(t, 17, inlineValues[0].Range.Start.Line)
	assert.Equal(t, 17, inlineValues[0].Range.End.Line)
}
