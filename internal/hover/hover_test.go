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
	indexMap := map[string]bool{}
	indexMap["hoverKey"] = true
	hoverIndexes[filePath] = indexMap

	return filePath
}

func Test_DeleteHover(t *testing.T) {
	filePath := setupFakeHover()
	DeleteHover(filePath)

	assert.Equal(t, len(hovers[filePath]), 0)
	assert.Equal(t, len(hoverIndexes[filePath]), 0)
}

func Test_ClearAllHovers(t *testing.T) {
	filePath := setupFakeHover()
	ClearAllHovers()

	assert.Equal(t, len(hovers[filePath]), 0)
	assert.Equal(t, len(hoverIndexes[filePath]), 0)
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
