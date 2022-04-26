package hover

import (
	"reflect"
	"testing"

	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/lsp"
	sglsp "github.com/sourcegraph/go-lsp"
)

// 3. pos on left character
// 4. pos on right character
// 5. multiline see above for start(left) end(right)

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

	path := "path/to/package.json"
	for _, tc := range tests {
		ClearAllHovers()
		hovers[path] = tc.hoverDetails

		result := GetHover(uri.PathToUri(path), tc.query)
		if !reflect.DeepEqual(tc.expected, result) {
			t.Fatalf("expected: %v, got: %v", tc.expected, result)
		}
	}
}
