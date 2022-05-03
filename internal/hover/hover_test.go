package hover

import (
	"reflect"
	"testing"

	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/lsp"

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
)

func setupFakeHover() sglsp.DocumentURI {
	fakeHover := []lsp.HoverDetails{
		{Range: sglsp.Range{
			Start: sglsp.Position{Line: 3, Character: 56},
			End:   sglsp.Position{Line: 5, Character: 80},
		},
		},
	}

	filePath := uri.PathToUri("file:///fake-file.txt")
	hovers[filePath] = fakeHover
	hoverIndexes[uri.PathFromUri(filePath+"rangepositionstuff")] = true

	return filePath
}

func Test_registerHovers(t *testing.T) {
	defer ClearAllHovers()
	documentUri := uri.PathToUri("fake-file.json")
	hover := lsp.Hover{
		Uri: documentUri,
		Hover: []lsp.HoverDetails{
			{
				Id: "test-id",
				Range: sglsp.Range{
					Start: sglsp.Position{
						Line:      10,
						Character: 14,
					},
					End: sglsp.Position{
						Line:      56,
						Character: 87,
					},
				},
				Message: "Very important hover",
			},
		},
	}

	registerHovers(hover)
	// assert de-duplication
	registerHovers(hover)

	assert.Equal(t, len(hovers[documentUri]), 1)
	assert.Equal(t, len(hoverIndexes), 1)
}

func Test_DeleteHover(t *testing.T) {
	documentUri := setupFakeHover()
	DeleteHover(documentUri)

	assert.Equal(t, len(hovers[documentUri]), 0)
	assert.Equal(t, len(hoverIndexes), 0)
}

func Test_ClearAllHovers(t *testing.T) {
	documentUri := setupFakeHover()
	ClearAllHovers()

	assert.Equal(t, len(hovers[documentUri]), 0)
	assert.Equal(t, len(hoverIndexes), 0)
}

func Test_GetHoverMultiline(t *testing.T) {
	tests := []struct {
		hoverDetails []lsp.HoverDetails
		query        sglsp.Position
		expected     lsp.HoverResult
	}{
		// multiline range
		{
			hoverDetails: []lsp.HoverDetails{{Range: sglsp.Range{
				Start: sglsp.Position{Line: 3, Character: 56},
				End:   sglsp.Position{Line: 5, Character: 80},
			},
				Message: "## Vulnerabilities found"}},
			query: sglsp.Position{Line: 4, Character: 66},
			expected: lsp.HoverResult{Contents: lsp.MarkupContent{
				Kind: "markdown", Value: "## Vulnerabilities found"},
			},
		},
		// exact line but within character range
		{
			hoverDetails: []lsp.HoverDetails{{Range: sglsp.Range{
				Start: sglsp.Position{Line: 4, Character: 56},
				End:   sglsp.Position{Line: 4, Character: 80},
			},
				Message: "## Vulnerabilities found"}},
			query: sglsp.Position{Line: 4, Character: 66},
			expected: lsp.HoverResult{Contents: lsp.MarkupContent{
				Kind: "markdown", Value: "## Vulnerabilities found"},
			},
		},
		// exact line and exact character
		{
			hoverDetails: []lsp.HoverDetails{{Range: sglsp.Range{
				Start: sglsp.Position{Line: 4, Character: 56},
				End:   sglsp.Position{Line: 4, Character: 56},
			},
				Message: "## Vulnerabilities found"}},
			query: sglsp.Position{Line: 4, Character: 56},
			expected: lsp.HoverResult{Contents: lsp.MarkupContent{
				Kind: "markdown", Value: "## Vulnerabilities found"},
			},
		},
		// hover left of the character position on exact line
		{
			hoverDetails: []lsp.HoverDetails{{Range: sglsp.Range{
				Start: sglsp.Position{Line: 4, Character: 56},
				End:   sglsp.Position{Line: 4, Character: 86},
			},
				Message: "## Vulnerabilities found"}},
			query: sglsp.Position{Line: 4, Character: 45},
			expected: lsp.HoverResult{Contents: lsp.MarkupContent{
				Kind: "markdown", Value: ""},
			},
		},
		// hover right of the character position on exact line
		{
			hoverDetails: []lsp.HoverDetails{{Range: sglsp.Range{
				Start: sglsp.Position{Line: 4, Character: 56},
				End:   sglsp.Position{Line: 4, Character: 86},
			},
				Message: "## Vulnerabilities found"}},
			query: sglsp.Position{Line: 4, Character: 105},
			expected: lsp.HoverResult{Contents: lsp.MarkupContent{
				Kind: "markdown", Value: ""},
			},
		},
	}

	path := uri.PathToUri("path/to/package.json")
	for _, tc := range tests {
		ClearAllHovers()
		hovers[path] = tc.hoverDetails

		result := GetHover(path, tc.query)
		if !reflect.DeepEqual(tc.expected, result) {
			t.Fatalf("expected: %v, got: %v", tc.expected, result)
		}
	}
}
