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

	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
)

func setupFakeHover() string {
	target := NewDefaultService(ux2.NewTestAnalytics()).(*DefaultHoverService)
	fakeHover := []Hover[Context]{
		{Range: snyk.Range{
			Start: snyk.Position{Line: 3, Character: 56},
			End:   snyk.Position{Line: 5, Character: 80},
		},
		},
	}

	filePath := "file:///fake-file.txt"
	target.hovers[filePath] = fakeHover
	target.hoverIndexes[filePath+"rangepositionstuff"] = true

	return filePath
}

func Test_registerHovers(t *testing.T) {
	target := NewDefaultService(ux2.NewTestAnalytics()).(*DefaultHoverService)
	hover, path := fakeDocumentHover()

	target.registerHovers(hover)
	// assert de-duplication
	target.registerHovers(hover)

	assert.Equal(t, len(target.hovers[path]), 1)
	assert.Equal(t, len(target.hoverIndexes), 1)
}

func Test_DeleteHover(t *testing.T) {
	target := NewDefaultService(ux2.NewTestAnalytics()).(*DefaultHoverService)
	documentUri := setupFakeHover()
	target.DeleteHover(documentUri)

	assert.Equal(t, len(target.hovers[documentUri]), 0)
	assert.Equal(t, len(target.hoverIndexes), 0)
}

func Test_ClearAllHovers(t *testing.T) {
	target := NewDefaultService(ux2.NewTestAnalytics()).(*DefaultHoverService)
	documentUri := setupFakeHover()
	target.ClearAllHovers()

	assert.Equal(t, len(target.hovers[documentUri]), 0)
	assert.Equal(t, len(target.hoverIndexes), 0)
}

func Test_GetHoverMultiline(t *testing.T) {
	target := NewDefaultService(ux2.NewTestAnalytics()).(*DefaultHoverService)

	tests := []struct {
		hoverDetails []Hover[Context]
		query        snyk.Position
		expected     Result
	}{
		// multiline range
		{
			hoverDetails: []Hover[Context]{{Range: snyk.Range{
				Start: snyk.Position{Line: 3, Character: 56},
				End:   snyk.Position{Line: 5, Character: 80},
			},
				Message: "## Vulnerabilities found"}},
			query: snyk.Position{Line: 4, Character: 66},
			expected: Result{Contents: MarkupContent{
				Kind: "markdown", Value: "## Vulnerabilities found"},
			},
		},
		// exact line but within character range
		{
			hoverDetails: []Hover[Context]{{Range: snyk.Range{
				Start: snyk.Position{Line: 4, Character: 56},
				End:   snyk.Position{Line: 4, Character: 80},
			},
				Message: "## Vulnerabilities found"}},
			query: snyk.Position{Line: 4, Character: 66},
			expected: Result{Contents: MarkupContent{
				Kind: "markdown", Value: "## Vulnerabilities found"},
			},
		},
		// exact line and exact character
		{
			hoverDetails: []Hover[Context]{{Range: snyk.Range{
				Start: snyk.Position{Line: 4, Character: 56},
				End:   snyk.Position{Line: 4, Character: 56},
			},
				Message: "## Vulnerabilities found"}},
			query: snyk.Position{Line: 4, Character: 56},
			expected: Result{Contents: MarkupContent{
				Kind: "markdown", Value: "## Vulnerabilities found"},
			},
		},
		// hover left of the character position on exact line
		{
			hoverDetails: []Hover[Context]{{Range: snyk.Range{
				Start: snyk.Position{Line: 4, Character: 56},
				End:   snyk.Position{Line: 4, Character: 86},
			},
				Message: "## Vulnerabilities found"}},
			query: snyk.Position{Line: 4, Character: 45},
			expected: Result{Contents: MarkupContent{
				Kind: "markdown", Value: ""},
			},
		},
		// hover right of the character position on exact line
		{
			hoverDetails: []Hover[Context]{{Range: snyk.Range{
				Start: snyk.Position{Line: 4, Character: 56},
				End:   snyk.Position{Line: 4, Character: 86},
			},
				Message: "## Vulnerabilities found"}},
			query: snyk.Position{Line: 4, Character: 105},
			expected: Result{Contents: MarkupContent{
				Kind: "markdown", Value: ""},
			},
		},
	}

	path := "path/to/package.json"
	for _, tc := range tests {
		target.ClearAllHovers()
		target.hovers[path] = tc.hoverDetails

		result := target.GetHover(path, tc.query)
		if !reflect.DeepEqual(tc.expected, result) {
			t.Fatalf("expected: %v, got: %v", tc.expected, result)
		}
	}
}

func Test_TracksAnalytics(t *testing.T) {
	analytics := ux2.NewTestAnalytics()
	target := NewDefaultService(analytics).(*DefaultHoverService)

	path := "path/to/package.json"

	target.ClearAllHovers()
	target.hovers[path] = []Hover[Context]{
		{
			Context: snyk.Issue{
				ID:               "issue",
				Severity:         snyk.Medium,
				IssueType:        snyk.ContainerVulnerability,
				AffectedFilePath: path,
			},
			Range: snyk.Range{
				Start: snyk.Position{Line: 3, Character: 56},
				End:   snyk.Position{Line: 5, Character: 80},
			},
			Message: "## Vulnerabilities found"},
	}

	target.GetHover(path, snyk.Position{Line: 4, Character: 66})
	assert.Len(t, analytics.GetAnalytics(), 1)
	assert.Equal(t, ux2.IssueHoverIsDisplayedProperties{
		IssueId:   "issue",
		IssueType: ux2.ContainerVulnerability,
		Severity:  ux2.Medium,
	}, analytics.GetAnalytics()[0])
}

func Test_SendingHovers_AfterClearAll_DoesNotBlock(t *testing.T) {
	service := NewDefaultService(ux2.NewTestAnalytics()).(*DefaultHoverService)
	service.ClearAllHovers()
	hover, _ := fakeDocumentHover()

	service.Channel() <- hover
	assert.Eventually(t, func() bool {
		return service.GetHover(hover.Path, snyk.Position{
			Line:      10,
			Character: 14,
		}).Contents.Value != ""
	}, 1*time.Second, 10*time.Millisecond)
}

func fakeDocumentHover() (DocumentHovers, string) {
	documentUri := "fake-file.json"
	hover := DocumentHovers{
		Path: documentUri,
		Hover: []Hover[Context]{
			{
				Id: "test-id",
				Range: snyk.Range{
					Start: snyk.Position{
						Line:      10,
						Character: 14,
					},
					End: snyk.Position{
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
