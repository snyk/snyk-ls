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
          "fingerprints": { "0": "4e1195df020de59e0d65a33a4279f1183e7ae4e5d980e309f8b55adff2e61c3e", "1": "68571817.2f8fe63a.d72e654c.2cb72cc6.3889ba3b.f9768b25.9f7df27c.2f57ef22.e691b550.178ac497.def7d7ff.a4a218b6.0478660a.48626284.c7aa846c.04f0f7a5", "identity": "109d79437bb9079b50bca1cf364a334ff8edbd7bab38997d73e8450e7122a9e5" }
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
          "fingerprints": { "0": "c02c0b965e023abee808f2b548d8d5193a8b5229be6f3121a6f16e2d41a449b3", "1": "c94d3162.3e499e75.77c10054.ce8e0834.4d1dae3c.dbd66e9d.07e7f9dc.f2a15e5d.533fa06c.b4fd2a7d.9e32d5bd.672c8618.7503d35f.0f88f1cc.74deb835.49a51850", "identity": "c0e0efc4fc56af4904d52e381eaf5c7090e91e217bc390997a119140dc672ff2" }
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
	engine := testutil.UnitTest(t)
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
	engine := testutil.UnitTest(t)
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
	engine := testutil.UnitTest(t)
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

func TestConvertSARIFJSONToIssues_DuplicateRunsAndResultsMatchFullUnmarshal(t *testing.T) {
	engine := testutil.UnitTest(t)
	logger := zerolog.Nop()
	inner := `{
  "version": "2.1.0",
  "runs": [
    {
      "tool": { "driver": { "name": "SnykCode", "rules": [] } },
      "results": [
        { "ruleId": "ignored/FirstRun", "message": { "text": "ignored first run" }, "locations": [], "fingerprints": {} }
      ]
    }
  ],
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "SnykCode",
          "rules": [
            {
              "id": "java/DuplicateRule",
              "name": "DuplicateRule",
              "shortDescription": { "text": "Duplicate rule" },
              "defaultConfiguration": { "level": "warning" },
              "help": { "markdown": "help-md", "text": "help" },
              "properties": { "categories": ["Security"], "tags": [] }
            }
          ]
        }
      },
      "properties": {},
      "results": [
        {
          "ruleId": "java/DuplicateRule",
          "level": "warning",
          "message": { "text": "ignored duplicate results" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "file:///tmp/ignored.java" },
                "region": { "startLine": 1, "endLine": 1, "startColumn": 1, "endColumn": 2 }
              }
            }
          ],
          "fingerprints": { "1": "133be358.f469d8d4.6302e868.382ef795.a17ba59d.854b6255.bca5d63f.96ca7145.85591433.52e49978.0711b1f8.e054793b.49e37dd4.4c133804.41753fbf.61c1b43c" }
        }
      ],
      "results": [
        {
          "ruleId": "java/DuplicateRule",
          "level": "warning",
          "message": { "text": "last duplicate wins" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "file:///tmp/last.java" },
                "region": { "startLine": 7, "endLine": 7, "startColumn": 3, "endColumn": 9 }
              }
            }
          ],
          "fingerprints": { "1": "53043482.4d2614b5.1604a9ec.fc6c50c7.d4aa1e8e.1e3ef15a.eaea6ed8.b6cea163.e88fd9c1.60001b50.de4c1baf.466e6dbb.670c2e50.8480b731.12be1d63.d9269ada", "identity": "52d2f06d9e325af363d551d93bdf43b4971933d0c3bcd5c72526c0a3c0572843" }
        }
      ]
    }
  ]
}`

	var full codeClientSarif.SarifResponse
	require.NoError(t, json.Unmarshal([]byte(inner), &full.Sarif))
	conv := SarifConverter{sarif: full, logger: &logger, hoverVerbosity: 0, engine: engine}
	want, err := conv.toIssues("")
	require.NoError(t, err)

	got, err := ConvertSARIFJSONToIssues(engine, &logger, 0, []byte(inner), "")

	require.NoError(t, err)
	assertIssueSlicesEqual(t, want, got)
}
