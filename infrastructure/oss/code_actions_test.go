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

package oss

import (
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

const propertyManagedPom = `<?xml version="1.0" encoding="UTF-8"?>
<project>
    <properties>
        <lib.cyclonedx-core-java.version>9.0.5</lib.cyclonedx-core-java.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.cyclonedx</groupId>
            <artifactId>cyclonedx-core-java</artifactId>
            <version>${lib.cyclonedx-core-java.version}</version>
        </dependency>
    </dependencies>
</project>
`

// F1: when a Maven dependency version is declared via a ${property} reference,
// the quickfix must edit the matching <properties> entry, not hardcode the
// version into the dependency block.
func Test_GetCodeActions_MavenPropertyVersion_RedirectsToProperty(t *testing.T) {
	engine := testutil.UnitTest(t)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingEnableSnykOssQuickFixActions), true)

	dir := t.TempDir()
	pomPath := filepath.Join(dir, "pom.xml")
	require.NoError(t, os.WriteFile(pomPath, []byte(propertyManagedPom), 0600))

	from := []string{"root@1.0.0", "org.cyclonedx:cyclonedx-core-java@9.0.5"}
	depNode := getDependencyNode(engine.GetLogger(), types.FilePath(pomPath), "maven", from, []byte(propertyManagedPom))
	require.NotNil(t, depNode)
	require.Equal(t, "${lib.cyclonedx-core-java.version}", depNode.Value)

	issue := mavenTestIssue()
	issue.From = from
	issue.UpgradePath = []any{"false", "org.cyclonedx:cyclonedx-core-java@11.0.1"}

	snykIssue := toIssue(engine, defaultResolver(t, engine), types.FilePath(dir), types.FilePath(pomPath), issue,
		&scanResult{}, nil, depNode, getLearnMock(t), error_reporting.NewTestErrorReporter(engine), "", nil)

	quickFix := findUpgradeAction(t, snykIssue.CodeActions)
	edit := (*quickFix.GetDeferredEdit())()

	edits := edit.Changes[pomPath]
	require.Len(t, edits, 1)
	assert.Equal(t, "11.0.1", edits[0].NewText)

	// The edit must target the property value (9.0.5), not the dependency <version>.
	propLine, propStart := locate(t, propertyManagedPom, "<lib.cyclonedx-core-java.version>", "9.0.5")
	assert.Equal(t, propLine, edits[0].Range.Start.Line, "edit should be on the <properties> line")
	assert.Equal(t, propStart, edits[0].Range.Start.Character)
	assert.Equal(t, propStart+len("9.0.5"), edits[0].Range.End.Character)
}

// F2: a deferred quickfix edit must refuse to apply if the file content at the
// cached range no longer matches what the action was created for. This prevents
// re-applying a stale edit (which corrupts the file).
func Test_AddQuickFixAction_RefusesStaleEdit(t *testing.T) {
	engine := testutil.UnitTest(t)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingEnableSnykOssQuickFixActions), true)

	dir := t.TempDir()
	pomPath := filepath.Join(dir, "pom.xml")
	original := "<x>\n            <version>9.0.5</version>\n</x>\n"
	require.NoError(t, os.WriteFile(pomPath, []byte(original), 0600))

	versionLine, versionStart := locate(t, original, "<version>", "9.0.5")
	versionRange := types.Range{
		Start: types.Position{Line: versionLine, Character: versionStart},
		End:   types.Position{Line: versionLine, Character: versionStart + len("9.0.5")},
	}

	action := AddQuickFixAction(engine, defaultResolver(t, engine), types.FilePath(pomPath), versionRange,
		nil, []byte(original), false, "maven",
		[]string{"root@1.0.0", "org:art@9.0.5"}, []any{"false", "org:art@11.0.1"}, nil)
	require.NotNil(t, action)

	// Simulate the buffer/file having already been changed (e.g. a previous apply):
	// the version token is no longer at the cached range.
	changed := "<x>\n            <version>11.0.1</version>\n</x>\n"
	require.NoError(t, os.WriteFile(pomPath, []byte(changed), 0600))

	edit := (*action.GetDeferredEdit())()
	assert.Empty(t, edit.Changes, "stale edit must not be applied")
}

func Test_AddQuickFixAction_AppliesWhenContentMatches(t *testing.T) {
	engine := testutil.UnitTest(t)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingEnableSnykOssQuickFixActions), true)

	dir := t.TempDir()
	pomPath := filepath.Join(dir, "pom.xml")
	original := "<x>\n            <version>9.0.5</version>\n</x>\n"
	require.NoError(t, os.WriteFile(pomPath, []byte(original), 0600))

	versionLine, versionStart := locate(t, original, "<version>", "9.0.5")
	versionRange := types.Range{
		Start: types.Position{Line: versionLine, Character: versionStart},
		End:   types.Position{Line: versionLine, Character: versionStart + len("9.0.5")},
	}

	action := AddQuickFixAction(engine, defaultResolver(t, engine), types.FilePath(pomPath), versionRange,
		nil, []byte(original), false, "maven",
		[]string{"root@1.0.0", "org:art@9.0.5"}, []any{"false", "org:art@11.0.1"}, nil)
	require.NotNil(t, action)

	edit := (*action.GetDeferredEdit())()
	edits := edit.Changes[pomPath]
	require.Len(t, edits, 1)
	assert.Equal(t, "11.0.1", edits[0].NewText)
	assert.Equal(t, versionRange, edits[0].Range)
}

// This is the customer-reported corruption (IDE-2139): the same cached quickfix
// applied twice without a rescan. With the fix the edit targets the
// <properties> value, so the dependency's <version>...</version> block — and
// crucially its closing tag — is never touched, and the file stays well-formed.
func Test_MavenPropertyQuickfix_AppliedTwice_DoesNotCorruptPom(t *testing.T) {
	engine := testutil.UnitTest(t)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingEnableSnykOssQuickFixActions), true)

	dir := t.TempDir()
	pomPath := filepath.Join(dir, "pom.xml")
	require.NoError(t, os.WriteFile(pomPath, []byte(propertyManagedPom), 0600))

	from := []string{"root@1.0.0", "org.cyclonedx:cyclonedx-core-java@9.0.5"}
	depNode := getDependencyNode(engine.GetLogger(), types.FilePath(pomPath), "maven", from, []byte(propertyManagedPom))
	require.NotNil(t, depNode)

	issue := mavenTestIssue()
	issue.From = from
	issue.UpgradePath = []any{"false", "org.cyclonedx:cyclonedx-core-java@11.0.1"}

	snykIssue := toIssue(engine, defaultResolver(t, engine), types.FilePath(dir), types.FilePath(pomPath), issue,
		&scanResult{}, nil, depNode, getLearnMock(t), error_reporting.NewTestErrorReporter(engine), "", nil)
	quickFix := findUpgradeAction(t, snykIssue.CodeActions)

	// Apply the very same cached edit twice, as happens when the file isn't
	// saved/rescanned between applies.
	result := propertyManagedPom
	for range 2 {
		edit := (*quickFix.GetDeferredEdit())()
		edits := edit.Changes[pomPath]
		require.Len(t, edits, 1)
		result = applySingleLineEdit(t, result, edits[0])
	}

	// The dependency block (and its closing tag) must be untouched.
	assert.Contains(t, result, "<version>${lib.cyclonedx-core-java.version}</version>",
		"dependency <version> block must remain a property reference")
	assert.Equal(t, strings.Count(propertyManagedPom, "</version>"), strings.Count(result, "</version>"),
		"no </version> closing tag may be deleted")
	assert.True(t, xmlIsWellFormed(result), "pom must remain well-formed XML")
}

func applySingleLineEdit(t *testing.T, content string, edit types.TextEdit) string {
	t.Helper()
	require.Equal(t, edit.Range.Start.Line, edit.Range.End.Line, "helper only supports single-line edits")
	lines := strings.Split(content, "\n")
	require.Less(t, edit.Range.Start.Line, len(lines))
	line := lines[edit.Range.Start.Line]
	end := edit.Range.End.Character
	if end > len(line) { // mimic an editor clamping an out-of-bounds range to EOL
		end = len(line)
	}
	lines[edit.Range.Start.Line] = line[:edit.Range.Start.Character] + edit.NewText + line[end:]
	return strings.Join(lines, "\n")
}

func xmlIsWellFormed(content string) bool {
	decoder := xml.NewDecoder(strings.NewReader(content))
	for {
		_, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return true
		}
		if err != nil {
			return false
		}
	}
}

func findUpgradeAction(t *testing.T, actions []types.CodeAction) types.CodeAction {
	t.Helper()
	for _, a := range actions {
		if strings.Contains(a.GetTitle(), "Upgrade to") {
			return a
		}
	}
	require.FailNow(t, "no upgrade quickfix action found")
	return nil
}

// locate returns the 0-based line and character offset of token within the line
// of content that contains anchor.
func locate(t *testing.T, content, anchor, token string) (int, int) {
	t.Helper()
	lines := strings.Split(content, "\n")
	for i, l := range lines {
		if strings.Contains(l, anchor) {
			idx := strings.Index(l, token)
			require.GreaterOrEqual(t, idx, 0)
			return i, idx
		}
	}
	require.FailNowf(t, "anchor not found", "anchor %q", anchor)
	return -1, -1
}
