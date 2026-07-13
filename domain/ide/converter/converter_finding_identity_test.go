/*
 * © 2024-2026 Snyk Limited
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

package converter

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

// realIacKey reproduces infrastructure/iac.getIssueKey exactly: the per-result-set
// Key is sha256(absoluteFilePath + lineNumber + publicID). It bakes the ABSOLUTE
// affected file path in, so the same finding scanned in a git-worktree copy (a
// different absolute path) gets a different Key. That is precisely why the Key
// cannot be the IaC grouping key; the location-independent publicID must be.
func realIacKey(absPath types.FilePath, lineNumber int, publicID string) string {
	sum := sha256.Sum256([]byte(string(absPath) + strconv.Itoa(lineNumber) + publicID))
	return hex.EncodeToString(sum[:16])
}

// Fix 2: when root!="" but filepath.Rel cannot relate the file to it, the fallback
// must log a warning (previously it returned the path silently, yielding a
// non-portable id with no diagnostic signal).
func TestRootRelativePath_LogsWarningOnRelError(t *testing.T) {
	var buf bytes.Buffer
	logger := zerolog.New(&buf)

	// A relative filePath cannot be made relative to an absolute root → Rel errors.
	rel := rootRelativePath(types.FilePath("/project"), types.FilePath("relative/x.go"), &logger)

	assert.Equal(t, "relative/x.go", rel, "on Rel error the forward-slashed path is returned")
	assert.Contains(t, buf.String(), "\"level\":\"warn\"", "a warning must be logged when Rel fails for a non-empty root")
}

// Fix 2: root=="" is an expected degenerate case (no folder context), handled
// before filepath.Rel — so it never logs, even for an absolute path.
func TestRootRelativePath_EmptyRoot_NoWarning(t *testing.T) {
	var buf bytes.Buffer
	logger := zerolog.New(&buf)

	rel := rootRelativePath(types.FilePath(""), types.FilePath("/abs/pkg/server.go"), &logger)

	assert.Equal(t, "/abs/pkg/server.go", rel)
	assert.Empty(t, buf.String(), "root=='' is not an error and must not emit a warning")
}

// Fix 2: root=="" with a relative input returns it unchanged (forward-slashed),
// embedding no absolute path.
func TestRootRelativePath_EmptyRoot_RelativeInput_NoAbsolutePath(t *testing.T) {
	rel := rootRelativePath(types.FilePath(""), types.FilePath("pkg/server.go"), nil)

	assert.Equal(t, "pkg/server.go", rel, "relative input must be returned unchanged, no absolute path embedded")
}

// IaC findings have an empty GetFindingId() (the scanner never sets one), so the
// converter uses the location-independent publicID as the grouping key. Two
// distinct rules at the SAME file+range have different publicIDs, so their
// composite identities differ — proving instance-uniqueness holds.
func TestToDiagnostics_IaC_UsesPublicIdGroupingKey_InstanceUnique(t *testing.T) {
	testutil.UnitTest(t)

	root := types.FilePath("/project")
	filePath := types.FilePath("/project/main.tf")
	r := types.Range{
		Start: types.Position{Line: 3, Character: 0},
		End:   types.Position{Line: 3, Character: 10},
	}

	issueA := &snyk.Issue{
		ID:               "iac-rule-A",
		Severity:         types.High,
		Product:          product.ProductInfrastructureAsCode,
		FindingId:        "", // IaC: never set by the scanner
		AffectedFilePath: filePath,
		ContentRoot:      root,
		Range:            r,
		AdditionalData:   snyk.IaCIssueData{Key: "key-publicid-A", PublicId: "SNYK-CC-A"},
	}
	issueB := &snyk.Issue{
		ID:               "iac-rule-B",
		Severity:         types.High,
		Product:          product.ProductInfrastructureAsCode,
		FindingId:        "", // same empty finding id, same file + range
		AffectedFilePath: filePath,
		ContentRoot:      root,
		Range:            r,
		AdditionalData:   snyk.IaCIssueData{Key: "key-publicid-B", PublicId: "SNYK-CC-B"},
	}

	diags := ToDiagnosticsForFolder([]types.Issue{issueA, issueB}, root, nil)
	require.Len(t, diags, 2)

	assert.NotEmpty(t, diags[0].Data.FindingId, "IaC FindingId must be non-empty")
	assert.NotEmpty(t, diags[1].Data.FindingId, "IaC FindingId must be non-empty")
	assert.NotEqual(t, diags[0].Data.FindingId, diags[1].Data.FindingId,
		"two distinct IaC rules at the same file+range must get different FindingIds")
}

// IaC identity must be worktree-portable (R3): the same finding scanned in the
// working tree and in a git-worktree copy of it must get the IDENTICAL FindingId.
// IaC has an empty GetFindingId(), and its per-result-set Key bakes the absolute
// path in, so using the Key as the grouping key gave the same finding a different
// FindingId across the worktree boundary. The grouping key must be the
// location-independent publicID; the root-relative path + range still individuate
// distinct instances.
func TestToDiagnostics_IaC_WorktreePortable_ViaPublicId(t *testing.T) {
	testutil.UnitTest(t)

	const publicID = "SNYK-CC-TF-1"
	const lineNumber = 3
	r := types.Range{
		Start: types.Position{Line: 3, Character: 0},
		End:   types.Position{Line: 3, Character: 12},
	}

	// Same finding, same relative path (main.tf), same range, same publicID —
	// scanned once in the working tree and once in a git-worktree copy mounted at a
	// different absolute root. The abs-path-baked Key differs between the two.
	origRoot := types.FilePath("/project")
	origFile := types.FilePath("/project/main.tf")
	origIssue := &snyk.Issue{
		ID:               "iac-rule",
		Severity:         types.High,
		Product:          product.ProductInfrastructureAsCode,
		FindingId:        "", // IaC never sets a finding id
		AffectedFilePath: origFile,
		ContentRoot:      origRoot,
		Range:            r,
		AdditionalData:   snyk.IaCIssueData{Key: realIacKey(origFile, lineNumber, publicID), PublicId: publicID},
	}

	wtRoot := types.FilePath("/tmp/worktree-abc")
	wtFile := types.FilePath("/tmp/worktree-abc/main.tf")
	wtIssue := &snyk.Issue{
		ID:               "iac-rule",
		Severity:         types.High,
		Product:          product.ProductInfrastructureAsCode,
		FindingId:        "",
		AffectedFilePath: wtFile,
		ContentRoot:      wtRoot,
		Range:            r,
		AdditionalData:   snyk.IaCIssueData{Key: realIacKey(wtFile, lineNumber, publicID), PublicId: publicID},
	}

	// Precondition: the abs-path-baked keys really do differ across the boundary,
	// so this test would pass trivially only if the Key had (wrongly) been ignored.
	require.NotEqual(t, origIssue.GetAdditionalData().GetKey(), wtIssue.GetAdditionalData().GetKey(),
		"precondition: IaC Key must differ across the worktree boundary (it bakes the abs path)")

	origDiags := ToDiagnosticsForFolder([]types.Issue{origIssue}, origRoot, nil)
	wtDiags := ToDiagnosticsForFolder([]types.Issue{wtIssue}, wtRoot, nil)
	require.Len(t, origDiags, 1)
	require.Len(t, wtDiags, 1)

	assert.NotEmpty(t, origDiags[0].Data.FindingId, "IaC FindingId must be non-empty")
	assert.Equal(t, origDiags[0].Data.FindingId, wtDiags[0].Data.FindingId,
		"IaC FindingId must be identical across the worktree boundary (grouping key = location-independent publicID)")

	// Instance-uniqueness still holds: a different publicID at the same location,
	// and the same publicID at a different range, both yield different identities.
	diffPublicID := &snyk.Issue{
		ID: "iac-rule-2", Severity: types.High, Product: product.ProductInfrastructureAsCode,
		AffectedFilePath: origFile, ContentRoot: origRoot, Range: r,
		AdditionalData: snyk.IaCIssueData{Key: realIacKey(origFile, lineNumber, "SNYK-CC-TF-2"), PublicId: "SNYK-CC-TF-2"},
	}
	r2 := types.Range{Start: types.Position{Line: 9, Character: 0}, End: types.Position{Line: 9, Character: 12}}
	samePublicIDDiffRange := &snyk.Issue{
		ID: "iac-rule", Severity: types.High, Product: product.ProductInfrastructureAsCode,
		AffectedFilePath: origFile, ContentRoot: origRoot, Range: r2,
		AdditionalData: snyk.IaCIssueData{Key: realIacKey(origFile, 9, publicID), PublicId: publicID},
	}
	otherDiags := ToDiagnosticsForFolder([]types.Issue{diffPublicID, samePublicIDDiffRange}, origRoot, nil)
	require.Len(t, otherDiags, 2)
	assert.NotEqual(t, origDiags[0].Data.FindingId, otherDiags[0].Data.FindingId,
		"different publicID must yield a different FindingId")
	assert.NotEqual(t, origDiags[0].Data.FindingId, otherDiags[1].Data.FindingId,
		"same publicID at a different range must yield a different FindingId")
}

// Fix 1: the code-action path must emit the SAME composite FindingId as the folder
// publishDiagnostics path for the same finding. Previously ToCodeAction ignored the
// folder root (using the issue's own sub-path ContentRoot), so a fixable finding's
// code-action FindingId diverged from the one published for it, breaking correlation.
func TestToCodeAction_FindingIdMatchesFolderPublishDiagnostics(t *testing.T) {
	testutil.UnitTest(t)

	canonicalRoot := types.FilePath("/project")
	subPath := types.FilePath("/project/src") // non-canonical: as produced by a sub-dir scan
	filePath := types.FilePath("/project/src/main.go")
	r := types.Range{
		Start: types.Position{Line: 10, Character: 4},
		End:   types.Position{Line: 10, Character: 20},
	}

	newIssue := func() *snyk.Issue {
		return &snyk.Issue{
			ID:               "code-rule-xss",
			Severity:         types.High,
			Product:          product.ProductCode,
			FindingId:        "asset-finding-v1-abc",
			AffectedFilePath: filePath,
			ContentRoot:      subPath,
			Range:            r,
			AdditionalData:   snyk.CodeIssueData{Key: "code-key-1"},
		}
	}

	// Folder publishDiagnostics path anchors to the canonical registered root.
	folderDiags := ToDiagnosticsForFolder([]types.Issue{newIssue()}, canonicalRoot, nil)
	require.Len(t, folderDiags, 1)
	folderFindingId := folderDiags[0].Data.FindingId

	// Code-action path must anchor to the SAME canonical root so the ids correlate.
	action := &snyk.CodeAction{Title: "Fix", OriginalTitle: "Fix"}
	lspAction := ToCodeAction(newIssue(), action, canonicalRoot)
	require.Len(t, lspAction.Diagnostics, 1)
	caFindingId := lspAction.Diagnostics[0].Data.FindingId

	assert.NotEmpty(t, caFindingId)
	assert.Equal(t, folderFindingId, caFindingId,
		"FindingId must be identical via the code-action path and the folder publishDiagnostics path")
}

// INT-005: when the issue's ContentRoot is a sub-path of the registered workspace folder,
// ToDiagnosticsForFolder must normalise ContentRoot to the canonical registered root and
// compute FindingId using the root-relative file path so the identity is worktree-portable.
func TestToDiagnostics_CanonicalContentRoot_RootRelativeFindingId(t *testing.T) {
	testutil.UnitTest(t)

	canonicalRoot := types.FilePath("/project")
	// The issue's ContentRoot is a sub-path (e.g. produced when a sub-directory is scanned).
	subPath := types.FilePath("/project/src")
	filePath := types.FilePath("/project/src/main.go")

	r := types.Range{
		Start: types.Position{Line: 10, Character: 4},
		End:   types.Position{Line: 10, Character: 20},
	}

	testIssue := &snyk.Issue{
		ID:               "code-rule-xss",
		Severity:         types.High,
		Product:          product.ProductCode,
		FindingId:        "asset-finding-v1-abc",
		AffectedFilePath: filePath,
		ContentRoot:      subPath, // deliberately set to sub-path to test normalisation
		Range:            r,
		AdditionalData: snyk.CodeIssueData{
			Key: "code-key-1",
		},
	}

	diagnostics := ToDiagnosticsForFolder([]types.Issue{testIssue}, canonicalRoot, nil)

	require.Len(t, diagnostics, 1)
	scanIssue := diagnostics[0].Data

	// ContentRoot must be the canonical registered root, not the sub-path.
	assert.Equal(t, canonicalRoot, scanIssue.ContentRoot,
		"ContentRoot must equal the canonical registered workspace folder root, not the scan sub-path")

	// FindingId must use the root-relative path (src/main.go) not the absolute path.
	// The expected identity is ComputeFindingIdentity using the root-relative path.
	rootRelPath := "src/main.go"
	expectedFindingId := util.ComputeFindingIdentity(
		"asset-finding-v1-abc",
		rootRelPath,
		r.Start.Line, r.Start.Character, r.End.Line, r.End.Character,
	)
	assert.Equal(t, expectedFindingId, scanIssue.FindingId,
		"FindingId must be computed from the root-relative file path for worktree portability")

	// Ensure FindingId is non-empty.
	assert.NotEmpty(t, scanIssue.FindingId, "FindingId must be non-empty")
}

// INT-005b: same finding scanned in a worktree copy and the original root gets the same
// FindingId when both are converted with their respective canonical roots, because the
// root-relative path is identical.
func TestToDiagnostics_CanonicalContentRoot_WorktreePortable(t *testing.T) {
	testutil.UnitTest(t)

	r := types.Range{
		Start: types.Position{Line: 5, Character: 2},
		End:   types.Position{Line: 5, Character: 15},
	}

	// Original workspace: /project/src/file.go
	originalRoot := types.FilePath("/project")
	originalIssue := &snyk.Issue{
		ID:               "rule/SQLi",
		Severity:         types.High,
		Product:          product.ProductCode,
		FindingId:        "asset-v1-sqli",
		AffectedFilePath: types.FilePath("/project/src/file.go"),
		ContentRoot:      originalRoot,
		Range:            r,
		AdditionalData:   snyk.CodeIssueData{Key: "key-1"},
	}

	// Worktree copy: /worktree/src/file.go (same relative path, different mount)
	worktreeRoot := types.FilePath("/worktree")
	worktreeIssue := &snyk.Issue{
		ID:               "rule/SQLi",
		Severity:         types.High,
		Product:          product.ProductCode,
		FindingId:        "asset-v1-sqli",
		AffectedFilePath: types.FilePath("/worktree/src/file.go"),
		ContentRoot:      worktreeRoot,
		Range:            r,
		AdditionalData:   snyk.CodeIssueData{Key: "key-1"},
	}

	originalDiags := ToDiagnosticsForFolder([]types.Issue{originalIssue}, originalRoot, nil)
	worktreeDiags := ToDiagnosticsForFolder([]types.Issue{worktreeIssue}, worktreeRoot, nil)

	require.Len(t, originalDiags, 1)
	require.Len(t, worktreeDiags, 1)

	assert.Equal(t, originalDiags[0].Data.FindingId, worktreeDiags[0].Data.FindingId,
		"FindingId must be identical across worktree boundary when root-relative path is the same")
}
