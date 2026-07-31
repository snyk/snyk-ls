/*
 * © 2022-2026 Snyk Limited
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

package types

import (
	"encoding/json"
	"testing"

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// UNIT-001: WorkspaceDiagnosticReport serializes with "kind":"full", "version":null,
// and the double-nested items shape the AC-verified wire contract requires.
func Test_WorkspaceDiagnosticReport_wireShape(t *testing.T) {
	report := WorkspaceDiagnosticReport{
		Items: []WorkspaceDocumentDiagnosticReport{
			{
				Kind:    "full",
				URI:     sglsp.DocumentURI("file:///foo.go"),
				Version: nil,
				Items:   []Diagnostic{},
			},
		},
	}

	b, err := json.Marshal(report)
	require.NoError(t, err)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(b, &raw))

	outerItems, ok := raw["items"].([]any)
	require.True(t, ok, "outer items must be an array")
	require.Len(t, outerItems, 1)

	item, ok := outerItems[0].(map[string]any)
	require.True(t, ok, "outer items[0] must be an object")
	assert.Equal(t, "full", item["kind"], `kind must be "full"`)
	// version must be present and null — *int with no omitempty guarantees this.
	versionRaw, hasVersion := item["version"]
	assert.True(t, hasVersion, "version key must be present in JSON (not omitted)")
	assert.Nil(t, versionRaw, "version must serialize as null when *int is nil")
	// Inner items must be present (double-nesting).
	_, hasInnerItems := item["items"]
	assert.True(t, hasInnerItems, "inner items key must be present (double-nested shape)")
}

// UNIT-002: WorkspaceDiagnosticParams deserialises previousResultIds using the
// field tag "value" (not "resultId") matching the AC wire contract.
func Test_WorkspaceDiagnosticParams_previousResultIdValueTag(t *testing.T) {
	raw := `{"previousResultIds":[{"uri":"file:///x","value":"r1"}]}`
	var params WorkspaceDiagnosticParams
	require.NoError(t, json.Unmarshal([]byte(raw), &params))
	require.Len(t, params.PreviousResultIDs, 1)
	assert.Equal(t, sglsp.DocumentURI("file:///x"), params.PreviousResultIDs[0].URI)
	assert.Equal(t, "r1", params.PreviousResultIDs[0].Value, `field tag must be "value"`)
}

// UNIT-003: Diagnostic.Data carries the identity fields the push path emits.
// These are existing types; this test pins their JSON tags so pull and push
// always emit byte-identical Data objects.
func Test_Diagnostic_dataCarriesIdentityTags(t *testing.T) {
	d := Diagnostic{
		Message: "something vulnerable",
		Data: ScanIssue{
			FindingId:   "abc-123",
			ContentRoot: "/workspace",
			IsNew:       true,
		},
	}

	b, err := json.Marshal(d)
	require.NoError(t, err)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(b, &raw))

	data, ok := raw["data"].(map[string]any)
	require.True(t, ok, "data field must be a JSON object")
	assert.Equal(t, "abc-123", data["findingId"], `findingId tag must be "findingId"`)
	assert.Equal(t, "/workspace", data["contentRoot"], `contentRoot tag must be "contentRoot"`)
	assert.Equal(t, true, data["isNew"], `isNew tag must be "isNew"`)
}

// UNIT-004: DiagnosticOptions serializes workspaceDiagnostics:true and
// interFileDependencies:false (both without omitempty so false is explicit).
func Test_DiagnosticOptions_wireShape(t *testing.T) {
	opts := DiagnosticOptions{
		WorkspaceDiagnostics:  true,
		InterFileDependencies: false,
	}

	b, err := json.Marshal(opts)
	require.NoError(t, err)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(b, &raw))

	assert.Equal(t, true, raw["workspaceDiagnostics"])
	assert.Equal(t, false, raw["interFileDependencies"])
}
