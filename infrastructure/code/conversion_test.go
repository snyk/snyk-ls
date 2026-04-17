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

package code

import (
	"encoding/json"
	"sort"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	codeClientSarif "github.com/snyk/code-client-go/sarif"

	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// minimal inner SARIF document (MCP path) with two security results for streaming vs full-unmarshal parity.
const conversionTestInnerSarif = `{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "SnykCode",
          "semanticVersion": "1.0.0",
          "version": "1.0.0",
          "rules": [
            {
              "id": "java/TestRule",
              "name": "TestRule",
              "shortDescription": { "text": "Test rule" },
              "defaultConfiguration": { "level": "warning" },
              "help": { "markdown": "help-md", "text": "help" },
              "properties": {
                "tags": ["java"],
                "categories": ["Security"],
                "cwe": ["CWE-1"]
              }
            }
          ]
        }
      },
      "properties": {},
      "results": [
        {
          "ruleId": "java/TestRule",
          "level": "warning",
          "message": { "text": "first finding" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "file:///tmp/a.java" },
                "region": { "startLine": 10, "endLine": 10, "startColumn": 1, "endColumn": 5 }
              }
            }
          ],
          "fingerprints": { "0": "", "1": "fp-a", "identity": "id-a" }
        },
        {
          "ruleId": "java/TestRule",
          "level": "warning",
          "message": { "text": "second finding" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "file:///tmp/b.java" },
                "region": { "startLine": 20, "endLine": 20, "startColumn": 2, "endColumn": 6 }
              }
            }
          ],
          "fingerprints": { "0": "", "1": "fp-b", "identity": "id-b" }
        }
      ]
    }
  ]
}`

func issueSortKey(i types.Issue) string {
	return string(i.GetAffectedFilePath()) + "\x00" + i.GetID() + "\x00" + i.GetMessage()
}

func sortIssuesForCompare(issues []types.Issue) []types.Issue {
	out := append([]types.Issue(nil), issues...)
	sort.Slice(out, func(a, b int) bool {
		return issueSortKey(out[a]) < issueSortKey(out[b])
	})
	return out
}

func assertIssueSlicesEqual(t *testing.T, want, got []types.Issue) {
	t.Helper()
	require.Equal(t, len(want), len(got))
	sw := sortIssuesForCompare(want)
	sg := sortIssuesForCompare(got)
	for i := range sw {
		w := sw[i]
		g := sg[i]
		require.Equal(t, w.GetID(), g.GetID())
		require.Equal(t, w.GetMessage(), g.GetMessage())
		require.Equal(t, w.GetAffectedFilePath(), g.GetAffectedFilePath())
		require.Equal(t, w.GetRange(), g.GetRange())
		require.Equal(t, w.GetSeverity(), g.GetSeverity())
		require.Equal(t, w.GetFingerprint(), g.GetFingerprint())
		require.Equal(t, w.GetGlobalIdentity(), g.GetGlobalIdentity())
	}
}

// TestConvertSARIFJSONToIssues_StreamMatchesFullUnmarshal checks streaming decode matches json.Unmarshal + toIssues.
func TestConvertSARIFJSONToIssues_StreamMatchesFullUnmarshal(t *testing.T) {
	t.Parallel()
	engine, _ := testutil.SmokeTestWithEngine(t, "")
	logger := zerolog.Nop()
	hover := 0
	basePath := ""

	var full codeClientSarif.SarifResponse
	require.NoError(t, json.Unmarshal([]byte(conversionTestInnerSarif), &full.Sarif))
	conv := SarifConverter{sarif: full, logger: &logger, hoverVerbosity: hover, engine: engine}
	want, err := conv.toIssues(types.FilePath(basePath))
	require.NoError(t, err)

	got, err := ConvertSARIFJSONToIssues(engine, &logger, hover, []byte(conversionTestInnerSarif), basePath)
	require.NoError(t, err)
	assertIssueSlicesEqual(t, want, got)
}

func TestConvertSARIFJSONToIssues_StreamMatchesFullUnmarshal_EmptyRuns(t *testing.T) {
	t.Parallel()
	engine, _ := testutil.SmokeTestWithEngine(t, "")
	logger := zerolog.Nop()
	inner := `{"$schema":"https://example/sarif.json","version":"2.1.0","runs":[]}`
	var full codeClientSarif.SarifResponse
	require.NoError(t, json.Unmarshal([]byte(inner), &full.Sarif))
	conv := SarifConverter{sarif: full, logger: &logger, hoverVerbosity: 0, engine: engine}
	want, err := conv.toIssues("")
	require.NoError(t, err)
	got, err := ConvertSARIFJSONToIssues(engine, &logger, 0, []byte(inner), "")
	require.NoError(t, err)
	require.Equal(t, len(want), len(got))
}

func TestConvertSARIFJSONToIssues_MalformedResultsArray(t *testing.T) {
	t.Parallel()
	engine, _ := testutil.SmokeTestWithEngine(t, "")
	logger := zerolog.Nop()
	// Valid first result, invalid second element in results array.
	sarif := `{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "SnykCode",
          "rules": [
            {
              "id": "r1",
              "name": "r1",
              "shortDescription": { "text": "r" },
              "defaultConfiguration": { "level": "warning" },
              "help": { "markdown": "", "text": "" },
              "properties": { "categories": ["Security"], "tags": [] }
            }
          ]
        }
      },
      "properties": {},
      "results": [
        {
          "ruleId": "r1",
          "level": "warning",
          "message": { "text": "ok" },
          "locations": [],
          "fingerprints": {}
        },
        not_valid_json_token
      ]
    }
  ]
}`
	_, err := ConvertSARIFJSONToIssues(engine, &logger, 0, []byte(sarif), "")
	require.Error(t, err)
}
