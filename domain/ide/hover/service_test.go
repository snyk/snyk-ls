/*
 * © 2022-2023 Snyk Limited All rights reserved.
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

package hover

import (
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func setupFakeHover(c *config.Config) (*DefaultHoverService, types.FilePath) {
	target := NewDefaultService(c).(*DefaultHoverService)
	fakeHover := []Hover[Context]{
		{Range: types.Range{
			Start: types.Position{Line: 3, Character: 56},
			End:   types.Position{Line: 5, Character: 80},
		},
		},
	}
	hvb := hoversByProduct{
		product.ProductCode: fakeHover,
	}

	filePath := types.FilePath("file:///fake-file.txt")
	target.hoversByFilePath[filePath] = hoversByProduct{}
	target.hoversByFilePath[filePath] = hvb
	path := string(filePath) + "rangepositionstuff" + product.ProductCode.ToProductCodename()
	target.hoverIndexes[path] = true

	return target, filePath
}

func Test_registerHovers(t *testing.T) {
	c := testutil.UnitTest(t)

	target := NewDefaultService(c).(*DefaultHoverService)
	hover, path := fakeDocumentHover()

	target.registerHovers(hover)
	// assert de-duplication
	target.registerHovers(hover)

	assert.Equal(t, len(target.hoversByFilePath[path]), 1)
	assert.Equal(t, len(target.hoverIndexes), 1)
}

func Test_DeleteHover(t *testing.T) {
	c := testutil.UnitTest(t)
	target, documentUri := setupFakeHover(c)
	target.DeleteHover(product.ProductCode, documentUri)

	assert.Equal(t, len(target.hoversByFilePath[documentUri]), 0)
	assert.Equal(t, len(target.hoverIndexes), 0)
}

func Test_DeleteHover_NonExistingProduct(t *testing.T) {
	c := testutil.UnitTest(t)
	target, documentUri := setupFakeHover(c)
	target.DeleteHover(product.ProductOpenSource, documentUri)

	// Assert no hovers were deleted
	assert.Equal(t, 1, len(target.hoversByFilePath[documentUri]))
	assert.Equal(t, len(target.hoverIndexes), 1)
}

func Test_ClearAllHovers(t *testing.T) {
	c := testutil.UnitTest(t)
	target, documentUri := setupFakeHover(c)
	target.ClearAllHovers()

	assert.Equal(t, len(target.hoversByFilePath[documentUri]), 0)
	assert.Equal(t, len(target.hoverIndexes), 0)
}

func Test_GetHoverMultiline(t *testing.T) {
	c := testutil.UnitTest(t)
	target := NewDefaultService(c).(*DefaultHoverService)

	tests := []struct {
		hoverDetails []Hover[Context]
		query        types.Position
		expected     Result
	}{
		// multiline range
		{
			hoverDetails: []Hover[Context]{{Range: types.Range{
				Start: types.Position{Line: 3, Character: 56},
				End:   types.Position{Line: 5, Character: 80},
			},
				Message: "## Issues found"}},
			query: types.Position{Line: 4, Character: 66},
			expected: Result{Contents: MarkupContent{
				Kind: "markdown", Value: "## Issues found"},
			},
		},
		// exact line but within character range
		{
			hoverDetails: []Hover[Context]{{Range: types.Range{
				Start: types.Position{Line: 4, Character: 56},
				End:   types.Position{Line: 4, Character: 80},
			},
				Message: "## Issues found"}},
			query: types.Position{Line: 4, Character: 66},
			expected: Result{Contents: MarkupContent{
				Kind: "markdown", Value: "## Issues found"},
			},
		},
		// exact line and exact character
		{
			hoverDetails: []Hover[Context]{{Range: types.Range{
				Start: types.Position{Line: 4, Character: 56},
				End:   types.Position{Line: 4, Character: 56},
			},
				Message: "## Issues found"}},
			query: types.Position{Line: 4, Character: 56},
			expected: Result{Contents: MarkupContent{
				Kind: "markdown", Value: "## Issues found"},
			},
		},
		// hover left of the character position on exact line
		{
			hoverDetails: []Hover[Context]{{Range: types.Range{
				Start: types.Position{Line: 4, Character: 56},
				End:   types.Position{Line: 4, Character: 86},
			},
				Message: "## Issues found"}},
			query: types.Position{Line: 4, Character: 45},
			expected: Result{Contents: MarkupContent{
				Kind: "markdown", Value: ""},
			},
		},
		// hover right of the character position on exact line
		{
			hoverDetails: []Hover[Context]{{Range: types.Range{
				Start: types.Position{Line: 4, Character: 56},
				End:   types.Position{Line: 4, Character: 86},
			},
				Message: "## Issues found"}},
			query: types.Position{Line: 4, Character: 105},
			expected: Result{Contents: MarkupContent{
				Kind: "markdown", Value: ""},
			},
		},
	}

	path := types.FilePath("path/to/package.json")
	for _, tc := range tests {
		target.ClearAllHovers()
		hvb := hoversByProduct{
			product.ProductCode: tc.hoverDetails,
		}

		target.hoversByFilePath[path] = hvb

		result := target.GetHover(path, tc.query)
		if !reflect.DeepEqual(tc.expected, result) {
			t.Fatalf("expected: %v, got: %v", tc.expected, result)
		}
	}
}

func Test_SendingHovers_AfterClearAll_DoesNotBlock(t *testing.T) {
	c := testutil.UnitTest(t)
	service := NewDefaultService(c).(*DefaultHoverService)
	service.ClearAllHovers()
	hover, _ := fakeDocumentHover()

	service.Channel() <- hover
	assert.Eventually(t, func() bool {
		return service.GetHover(hover.Path, types.Position{
			Line:      10,
			Character: 14,
		}).Contents.Value != ""
	}, 1*time.Second, 10*time.Millisecond)
}

func fakeDocumentHover() (DocumentHovers, types.FilePath) {
	documentUri := types.FilePath("fake-file.json")
	hover := DocumentHovers{
		Path: documentUri,
		Hover: []Hover[Context]{
			{
				Id: "test-id",
				Range: types.Range{
					Start: types.Position{
						Line:      10,
						Character: 14,
					},
					End: types.Position{
						Line:      56,
						Character: 87,
					},
				},
				Message: "Very important hover",
			},
		},
	}
	return hover, documentUri
}
