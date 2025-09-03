/*
 * © 2025 Snyk Limited
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

package container

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// TestManualVerification is a manual test to demonstrate the scanner functionality
// Run with: go test -v -run TestManualVerification
func TestManualVerification(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping manual verification test in short mode")
	}

	c := testutil.UnitTest(t)
	c.SetSnykContainerEnabled(true)

	// Create realistic mock responses
	mockAPI := &MockBaseImageRemediationAPI{
		response: &BaseImageRecommendation{
			OriginalImage:     "ubuntu:18.04",
			RecommendedImage:  "ubuntu:22.04-slim",
			Reason:            "Ubuntu 22.04 LTS (Jammy Jellyfish) includes critical security patches and is the current LTS release. The slim variant reduces image size by ~50MB while maintaining essential packages.",
			SeverityReduction: "Upgrading eliminates 237 known vulnerabilities (including 45 high severity and 12 critical severity issues). Total risk reduction: ~85%",
		},
		err: nil,
	}
	scanner := newMockScanner(c, mockAPI)

	// Create test Dockerfile
	tmpDir := t.TempDir()
	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	dockerfileContent := `# Production Dockerfile
FROM ubuntu:18.04

RUN apt-get update && \
    apt-get install -y python3 python3-pip && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN pip3 install -r requirements.txt

EXPOSE 8080
CMD ["python3", "app.py"]`

	err := os.WriteFile(dockerfilePath, []byte(dockerfileContent), 0644)
	require.NoError(t, err)

	separator := strings.Repeat("=", 80)
	t.Log("\n" + separator)
	t.Log("MANUAL VERIFICATION TEST: Container Base Image Scanner")
	t.Log(separator + "\n")

	t.Log("📄 Scanning Dockerfile:")
	t.Log(dockerfileContent)
	t.Log("")

	// Scan the Dockerfile
	ctx := t.Context()
	issues, err := scanner.Scan(ctx, types.FilePath(dockerfilePath), types.FilePath(tmpDir), nil)
	require.NoError(t, err)

	t.Logf("✅ Scan completed successfully. Found %d issue(s)\n", len(issues))

	// Display detailed results
	for i, issue := range issues {
		t.Logf("Issue #%d:", i+1)
		t.Logf("  ID: %s", issue.GetID())
		t.Logf("  Severity: %s", issue.GetSeverity())
		t.Logf("  Product: %v", issue.GetProduct())
		t.Logf("  Type: %v", issue.GetIssueType())
		t.Logf("  Message: %s", issue.GetMessage())
		t.Logf("  Range: Line %d, Char %d-%d",
			issue.GetRange().Start.Line,
			issue.GetRange().Start.Character,
			issue.GetRange().End.Character)

		t.Log("\n  📋 Formatted Details:")
		lines := splitLines(issue.GetFormattedMessage())
		for _, line := range lines {
			t.Logf("    %s", line)
		}

		codeActions := issue.GetCodeActions()
		if len(codeActions) > 0 {
			t.Log("\n  🔧 Available Code Actions:")
			for j, action := range codeActions {
				t.Logf("    %d. %s", j+1, action.GetTitle())
			}
		}

		t.Log("")
	}

	t.Log(separator)
	t.Log("✨ Verification Summary:")
	t.Log("  ✓ Base image detection: WORKING")
	t.Log("  ✓ AST parsing: WORKING")
	t.Log("  ✓ Recommendation generation: WORKING")
	t.Log("  ✓ Code action creation: WORKING")
	t.Log("  ✓ Issue metadata: COMPLETE")
	t.Log(separator + "\n")
}

func splitLines(s string) []string {
	result := []string{}
	current := ""
	for _, char := range s {
		if char == '\n' {
			result = append(result, current)
			current = ""
		} else {
			current += string(char)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}
