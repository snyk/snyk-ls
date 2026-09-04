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
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// Two distinct Snyk Code findings (distinct "0"/identity, different lines) that
// share one SARIF "1" (Num1) fingerprint — Num1 is a structural similarity hash,
// so identical code at different locations legitimately collides.
const sharedNum1Sarif = `{
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
              "id": "csharp/NoHardcodedCredentials",
              "name": "NoHardcodedCredentials",
              "shortDescription": { "text": "Use of Hardcoded Credentials" },
              "defaultConfiguration": { "level": "warning" },
              "help": { "markdown": "help-md", "text": "help" },
              "properties": { "tags": ["csharp"], "categories": ["Security"], "cwe": ["CWE-798"] }
            }
          ]
        }
      },
      "properties": {},
      "results": [
        {
          "ruleId": "csharp/NoHardcodedCredentials",
          "level": "warning",
          "message": { "text": "hardcoded credential at line 158" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "src/DocumentationViewModel.cs" },
                "region": { "startLine": 158, "endLine": 158, "startColumn": 30, "endColumn": 40 }
              }
            }
          ],
          "fingerprints": {
            "0": "56fb6bbc064fc63a9d83c4b36b26dc88085f9e9acefb75c810be9203715d4690",
            "1": "cf781d8d.f3a3cc05.7109edc5.085098b9.09f51587.b1efc2aa.631814f5.2364a525.ec8818e9.dbd7ba45.0f2fc7f7.95fb55a5.58fbaf5d.ebd68aca.ce17ca18.0bc9476e",
            "identity": "4d30df37c5fbdd605db8c49027071684a09d0ea5812f2c36e8120b60dbc2869d"
          }
        },
        {
          "ruleId": "csharp/NoHardcodedCredentials",
          "level": "warning",
          "message": { "text": "hardcoded credential at line 174" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "src/DocumentationViewModel.cs" },
                "region": { "startLine": 174, "endLine": 174, "startColumn": 30, "endColumn": 40 }
              }
            }
          ],
          "fingerprints": {
            "0": "5619caedf12c358ec501c296744fb5de6e3e1e7f65f22ce01bbaf8a525a76502",
            "1": "cf781d8d.f3a3cc05.7109edc5.085098b9.09f51587.b1efc2aa.631814f5.2364a525.ec8818e9.dbd7ba45.0f2fc7f7.95fb55a5.58fbaf5d.ebd68aca.ce17ca18.0bc9476e",
            "identity": "041533e5b99edaf38310c828b1dae8806b5c7211037212f4f306ab1ac8b37fa9"
          }
        }
      ]
    }
  ]
}`

// TestCode_SharedNum1_ConvertedThenCountedIndividually locks the end-to-end
// chain: the converter sources a Code issue's fingerprint from the SARIF "1"
// (Num1), and because Num1 is not a per-finding identity, two distinct findings
// that share it must still be counted individually. Prevents both a regression
// in the Num1→Fingerprint mapping and a re-introduction of the non-Secrets
// fingerprint collapse.
func TestCode_SharedNum1_ConvertedThenCountedIndividually(t *testing.T) {
	engine := testutil.UnitTest(t)
	logger := zerolog.Nop()

	const sharedNum1 = "cf781d8d.f3a3cc05.7109edc5.085098b9.09f51587.b1efc2aa.631814f5.2364a525.ec8818e9.dbd7ba45.0f2fc7f7.95fb55a5.58fbaf5d.ebd68aca.ce17ca18.0bc9476e"

	issues, err := ConvertSARIFJSONToIssues(engine, &logger, 0, []byte(sharedNum1Sarif), "")
	require.NoError(t, err)
	require.Len(t, issues, 2, "two SARIF results → two Code issues")

	// The converter maps SARIF "1" (Num1) → issue fingerprint, so both findings
	// carry the same fingerprint despite being distinct findings (distinct
	// identities).
	for _, iss := range issues {
		require.Equal(t, product.ProductCode, iss.GetProduct())
		require.Equal(t, sharedNum1, iss.GetFingerprint(), "Code fingerprint must be the SARIF Num1 value")
	}
	require.NotEqual(t, issues[0].GetGlobalIdentity(), issues[1].GetGlobalIdentity(),
		"the two findings are distinct (different identity fingerprints)")

	// Code is not collapsed by fingerprint: both distinct findings are counted,
	// even though their Num1 is identical.
	require.Len(t, types.DeduplicateByFingerprint(issues), 2,
		"Code: distinct findings sharing a Num1 must each be counted")
}
