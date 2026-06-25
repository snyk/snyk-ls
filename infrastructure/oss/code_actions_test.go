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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/ast"
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
	edits := applyMavenUpgradeQuickfix(t, propertyManagedPom)
	require.Len(t, edits, 1)
	assert.Equal(t, "11.0.1", edits[0].NewText)

	// The edit must target the property value (9.0.5), not the dependency <version>.
	propLine, propStart := locate(t, propertyManagedPom, "<lib.cyclonedx-core-java.version>", "9.0.5")
	assert.Equal(t, propLine, edits[0].Range.Start.Line, "edit should be on the <properties> line")
	assert.Equal(t, propStart, edits[0].Range.Start.Character)
	assert.Equal(t, propStart+len("9.0.5"), edits[0].Range.End.Character)
}

// A CRLF pom must flow through parse -> quickfix -> stale-edit guard correctly.
// The parser strips \r before computing positions, and the apply-time guard reads
// the raw CRLF file from disk; textAtRange normalizes \r so the two stay aligned
// and the guard passes (edit produced) instead of spuriously refusing on Windows.
func Test_GetCodeActions_MavenPropertyVersion_CRLF(t *testing.T) {
	crlf := strings.ReplaceAll(propertyManagedPom, "\n", "\r\n")
	edits := applyMavenUpgradeQuickfix(t, crlf)
	require.Len(t, edits, 1, "guard must pass and produce an edit for a CRLF pom")
	assert.Equal(t, "11.0.1", edits[0].NewText)

	// Positions are those of the CR-stripped content (LF version), proving the
	// parser normalized line endings before computing offsets.
	propLine, propStart := locate(t, propertyManagedPom, "<lib.cyclonedx-core-java.version>", "9.0.5")
	assert.Equal(t, propLine, edits[0].Range.Start.Line)
	assert.Equal(t, propStart, edits[0].Range.Start.Character)
	assert.Equal(t, propStart+len("9.0.5"), edits[0].Range.End.Character)
}

const childPomWithParentProperty = `<?xml version="1.0" encoding="UTF-8"?>
<project>
    <parent>
        <relativePath>../parent/pom.xml</relativePath>
    </parent>
    <dependencies>
        <dependency>
            <groupId>org.cyclonedx</groupId>
            <artifactId>cyclonedx-core-java</artifactId>
            <version>${foo.version}</version>
        </dependency>
    </dependencies>
</project>
`

const parentPomWithProperty = `<?xml version="1.0" encoding="UTF-8"?>
<project>
    <properties>
        <foo.version>9.0.5</foo.version>
    </properties>
</project>
`

// When a child dependency's version references a property defined in a PARENT
// pom, resolveMavenPropertyNode must walk tree.ParentTree and the quickfix edit
// must target the parent pom's <properties> entry — not the child.
func Test_GetCodeActions_MavenPropertyInParentPom_RedirectsToParent(t *testing.T) {
	engine := testutil.UnitTest(t)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingEnableSnykOssQuickFixActions), true)

	dir := t.TempDir()
	childDir := filepath.Join(dir, "child")
	parentDir := filepath.Join(dir, "parent")
	require.NoError(t, os.MkdirAll(childDir, 0755))
	require.NoError(t, os.MkdirAll(parentDir, 0755))
	childPath := filepath.Join(childDir, "pom.xml")
	parentPath := filepath.Join(parentDir, "pom.xml")
	require.NoError(t, os.WriteFile(childPath, []byte(childPomWithParentProperty), 0600))
	require.NoError(t, os.WriteFile(parentPath, []byte(parentPomWithProperty), 0600))

	from := []string{"root@1.0.0", "org.cyclonedx:cyclonedx-core-java@9.0.5"}
	depNode := getDependencyNode(engine.GetLogger(), types.FilePath(childPath), "maven", from, []byte(childPomWithParentProperty), types.FilePath(dir))
	require.NotNil(t, depNode)
	require.Equal(t, "${foo.version}", depNode.Value)

	issue := mavenTestIssue()
	issue.From = from
	issue.UpgradePath = []any{"false", "org.cyclonedx:cyclonedx-core-java@11.0.1"}

	snykIssue := toIssue(engine, defaultResolver(t, engine), types.FilePath(dir), types.FilePath(childPath), issue,
		&scanResult{}, nil, depNode, getLearnMock(t), error_reporting.NewTestErrorReporter(engine), "", nil)

	quickFix := findUpgradeAction(t, snykIssue.CodeActions)
	edit := (*quickFix.GetDeferredEdit())()

	// The edit must target the PARENT pom, not the child.
	require.Empty(t, edit.Changes[childPath], "child pom must not be edited")
	edits := edit.Changes[parentPath]
	require.Len(t, edits, 1)
	assert.Equal(t, "11.0.1", edits[0].NewText)

	propLine, propStart := locate(t, parentPomWithProperty, "<foo.version>", "9.0.5")
	assert.Equal(t, propLine, edits[0].Range.Start.Line, "edit should target the parent <properties> line")
	assert.Equal(t, propStart, edits[0].Range.Start.Character)
	assert.Equal(t, propStart+len("9.0.5"), edits[0].Range.End.Character)
}

// childPomVersionlessDep declares the dependency without a <version>; the version
// is inherited from the parent pom, so the child dependency node resolves with an
// empty Value and a LinkedParentDependencyNode.
const childPomVersionlessDep = `<?xml version="1.0" encoding="UTF-8"?>
<project>
    <parent>
        <relativePath>../parent/pom.xml</relativePath>
    </parent>
    <dependencies>
        <dependency>
            <groupId>org.cyclonedx</groupId>
            <artifactId>cyclonedx-core-java</artifactId>
        </dependency>
    </dependencies>
</project>
`

// parentPomDepWithProperty declares the dependency WITH a version, but that version
// is itself a ${property} reference resolved from the parent's own <properties>.
const parentPomDepWithProperty = `<?xml version="1.0" encoding="UTF-8"?>
<project>
    <properties>
        <foo.version>9.0.5</foo.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.cyclonedx</groupId>
            <artifactId>cyclonedx-core-java</artifactId>
            <version>${foo.version}</version>
        </dependency>
    </dependencies>
</project>
`

// When the dependency version lives in a PARENT pom and that parent's <version> is
// itself a ${property} reference, the quickfix must follow the LinkedParentDependencyNode
// into the parent and redirect the edit to the parent's <properties> entry — not
// hardcode the upgraded version into the parent's <version>, which would orphan the
// property and corrupt the file on re-apply.
func Test_GetCodeActions_MavenParentPomPropertyVersion_RedirectsToParentProperty(t *testing.T) {
	engine := testutil.UnitTest(t)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingEnableSnykOssQuickFixActions), true)

	dir := t.TempDir()
	childDir := filepath.Join(dir, "child")
	parentDir := filepath.Join(dir, "parent")
	require.NoError(t, os.MkdirAll(childDir, 0755))
	require.NoError(t, os.MkdirAll(parentDir, 0755))
	childPath := filepath.Join(childDir, "pom.xml")
	parentPath := filepath.Join(parentDir, "pom.xml")
	require.NoError(t, os.WriteFile(childPath, []byte(childPomVersionlessDep), 0600))
	require.NoError(t, os.WriteFile(parentPath, []byte(parentPomDepWithProperty), 0600))

	from := []string{"root@1.0.0", "org.cyclonedx:cyclonedx-core-java@9.0.5"}
	depNode := getDependencyNode(engine.GetLogger(), types.FilePath(childPath), "maven", from, []byte(childPomVersionlessDep), types.FilePath(dir))
	require.NotNil(t, depNode)
	// The child has no version, so the version is inherited from the parent.
	require.Empty(t, depNode.Value, "child dependency must have no inline version")
	require.NotNil(t, depNode.LinkedParentDependencyNode, "version should be linked from the parent pom")
	require.Equal(t, "${foo.version}", depNode.LinkedParentDependencyNode.Value)

	issue := mavenTestIssue()
	issue.From = from
	issue.UpgradePath = []any{"false", "org.cyclonedx:cyclonedx-core-java@11.0.1"}

	snykIssue := toIssue(engine, defaultResolver(t, engine), types.FilePath(dir), types.FilePath(childPath), issue,
		&scanResult{}, nil, depNode, getLearnMock(t), error_reporting.NewTestErrorReporter(engine), "", nil)

	quickFix := findUpgradeAction(t, snykIssue.CodeActions)
	edit := (*quickFix.GetDeferredEdit())()

	// The edit must target the parent pom's <properties> entry, not its <version>,
	// and the child pom must be untouched.
	require.Empty(t, edit.Changes[childPath], "child pom must not be edited")
	edits := edit.Changes[parentPath]
	require.Len(t, edits, 1)
	assert.Equal(t, "11.0.1", edits[0].NewText)

	propLine, propStart := locate(t, parentPomDepWithProperty, "<foo.version>", "9.0.5")
	assert.Equal(t, propLine, edits[0].Range.Start.Line, "edit should target the parent <properties> line, not <version>")
	assert.Equal(t, propStart, edits[0].Range.Start.Character)
	assert.Equal(t, propStart+len("9.0.5"), edits[0].Range.End.Character)
}

const indirectPropertyPom = `<?xml version="1.0" encoding="UTF-8"?>
<project>
    <properties>
        <a.version>${b.version}</a.version>
        <b.version>9.0.5</b.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.cyclonedx</groupId>
            <artifactId>cyclonedx-core-java</artifactId>
            <version>${a.version}</version>
        </dependency>
    </dependencies>
</project>
`

// When a version property points at another property (${a.version} -> ${b.version}
// -> 9.0.5), the quickfix must follow the indirection and edit the property that
// holds the concrete value (b.version), not overwrite the intermediate reference.
func Test_GetCodeActions_MavenPropertyIndirection_FollowsChainToConcreteValue(t *testing.T) {
	edits := applyMavenUpgradeQuickfix(t, indirectPropertyPom)
	require.Len(t, edits, 1)
	assert.Equal(t, "11.0.1", edits[0].NewText)

	// The edit must target b.version (the concrete 9.0.5), not a.version (${b.version}).
	propLine, propStart := locate(t, indirectPropertyPom, "<b.version>", "9.0.5")
	assert.Equal(t, propLine, edits[0].Range.Start.Line, "edit should target the concrete property b.version")
	assert.Equal(t, propStart, edits[0].Range.Start.Character)
	assert.Equal(t, propStart+len("9.0.5"), edits[0].Range.End.Character)
}

const unresolvedPropertyPom = `<?xml version="1.0" encoding="UTF-8"?>
<project>
    <dependencies>
        <dependency>
            <groupId>org.cyclonedx</groupId>
            <artifactId>cyclonedx-core-java</artifactId>
            <version>${missing.version}</version>
        </dependency>
    </dependencies>
</project>
`

// When the version is a ${property} reference but the property cannot be resolved
// (absent from <properties> and no parent pom), resolveMavenPropertyNode returns
// nil and the quickfix must fall back to editing the dependency <version> block
// itself — producing a sensible edit rather than panicking or targeting nothing.
func Test_GetCodeActions_MavenUnresolvedProperty_FallsBackToDependencyVersion(t *testing.T) {
	edits := applyMavenUpgradeQuickfix(t, unresolvedPropertyPom)
	require.Len(t, edits, 1)
	assert.Equal(t, "11.0.1", edits[0].NewText)

	// Fallback: the edit must target the dependency <version> value
	// (${missing.version}), since the property could not be resolved.
	verLine, verStart := locate(t, unresolvedPropertyPom, "<version>", "${missing.version}")
	assert.Equal(t, verLine, edits[0].Range.Start.Line, "edit should target the dependency <version> line")
	assert.Equal(t, verStart, edits[0].Range.Start.Character)
	assert.Equal(t, verStart+len("${missing.version}"), edits[0].Range.End.Character)
}

// F2: a deferred quickfix edit must refuse to apply if the file content at the
// cached range no longer matches what the action was created for. This prevents
// re-applying a stale edit (which corrupts the file).
func Test_addQuickFixAction_RefusesStaleEdit(t *testing.T) {
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

	action := addQuickFixAction(engine, defaultResolver(t, engine), types.FilePath(pomPath), versionRange,
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

// When a snapshot is provided but the text at the fix range cannot be read (here:
// a multi-line range, which textAtRange rejects), the guard cannot protect the
// edit. addQuickFixAction must drop the action rather than create an unguarded one.
func Test_addQuickFixAction_DropsActionWhenSnapshotProvidedButRangeUnreadable(t *testing.T) {
	engine := testutil.UnitTest(t)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingEnableSnykOssQuickFixActions), true)

	dir := t.TempDir()
	pomPath := filepath.Join(dir, "pom.xml")
	original := "<x>\n            <version>9.0.5</version>\n</x>\n"
	require.NoError(t, os.WriteFile(pomPath, []byte(original), 0600))

	// A multi-line range: textAtRange returns ok=false for this.
	multiLineRange := types.Range{
		Start: types.Position{Line: 0, Character: 0},
		End:   types.Position{Line: 1, Character: 5},
	}

	action := addQuickFixAction(engine, defaultResolver(t, engine), types.FilePath(pomPath), multiLineRange,
		nil, []byte(original), false, "maven",
		[]string{"root@1.0.0", "org:art@9.0.5"}, []any{"false", "org:art@11.0.1"}, nil)
	assert.Nil(t, action, "action must be dropped when the snapshot cannot guard the edit")
}

func Test_addQuickFixAction_AppliesWhenContentMatches(t *testing.T) {
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

	action := addQuickFixAction(engine, defaultResolver(t, engine), types.FilePath(pomPath), versionRange,
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
	depNode := getDependencyNode(engine.GetLogger(), types.FilePath(pomPath), "maven", from, []byte(propertyManagedPom), types.FilePath(dir))
	require.NotNil(t, depNode)

	issue := mavenTestIssue()
	issue.From = from
	issue.UpgradePath = []any{"false", "org.cyclonedx:cyclonedx-core-java@11.0.1"}

	snykIssue := toIssue(engine, defaultResolver(t, engine), types.FilePath(dir), types.FilePath(pomPath), issue,
		&scanResult{}, nil, depNode, getLearnMock(t), error_reporting.NewTestErrorReporter(engine), "", nil)
	quickFix := findUpgradeAction(t, snykIssue.CodeActions)

	// Apply the cached edit, persisting the result to disk between applies as a
	// real save would. The first apply upgrades the property; the second must be
	// refused (single-shot latch + stale-edit guard) so the value is never
	// double-applied into 11.0.11.
	result := propertyManagedPom

	edit := (*quickFix.GetDeferredEdit())()
	edits := edit.Changes[pomPath]
	require.Len(t, edits, 1, "first apply should produce the upgrade edit")
	result = applySingleLineEdit(t, result, edits[0])
	require.NoError(t, os.WriteFile(pomPath, []byte(result), 0600))

	edit = (*quickFix.GetDeferredEdit())()
	assert.Empty(t, edit.Changes, "second apply must be refused, not re-applied")

	// The property value is upgraded exactly once.
	assert.Contains(t, result, "<lib.cyclonedx-core-java.version>11.0.1</lib.cyclonedx-core-java.version>",
		"property value must be upgraded exactly once (not 11.0.11)")
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

// resolveMavenPropertyNode must terminate and fall back (return nil) rather than
// loop forever or mis-resolve when a property chain cycles or exceeds the depth
// limit, and must still resolve a chain right up to the limit. A nil result makes
// the quickfix fall back to editing the dependency <version>.
func Test_resolveMavenPropertyNode_CycleAndDepthBounds(t *testing.T) {
	engine := testutil.UnitTest(t)
	from := []string{"root@1.0.0", "org.cyclonedx:cyclonedx-core-java@9.0.5"}
	depFor := func(content string) *ast.Node {
		return getDependencyNode(engine.GetLogger(), types.FilePath("pom.xml"), "maven", from, []byte(content), "")
	}
	wrap := func(properties, versionRef string) string {
		return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<project>\n    <properties>\n" +
			properties +
			"    </properties>\n    <dependencies>\n        <dependency>\n" +
			"            <groupId>org.cyclonedx</groupId>\n" +
			"            <artifactId>cyclonedx-core-java</artifactId>\n" +
			"            <version>" + versionRef + "</version>\n" +
			"        </dependency>\n    </dependencies>\n</project>\n"
	}

	// Termination contract: a cyclic reference must not resolve. Note this is a
	// behavior contract, not an isolation of the `seen` cycle guard specifically —
	// the maxPropertyIndirectionDepth backstop also bounds an a<->b bounce to nil,
	// so the two guards are outcome-equivalent here. The test guards against a
	// regression that removed all bounding (which would loop forever).
	t.Run("reference cycle terminates and does not resolve", func(t *testing.T) {
		props := "        <a.version>${b.version}</a.version>\n        <b.version>${a.version}</b.version>\n"
		depNode := depFor(wrap(props, "${a.version}"))
		require.NotNil(t, depNode)
		assert.Nil(t, resolveMavenPropertyNode(depNode), "an a<->b reference cycle must not resolve")
	})

	t.Run("indirection deeper than the limit returns nil", func(t *testing.T) {
		// p0 -> p1 -> ... with the chain longer than maxPropertyIndirectionDepth;
		// only the last is concrete, so the limit is hit before reaching it.
		chain := maxPropertyIndirectionDepth + 4
		var props strings.Builder
		for i := range chain {
			fmt.Fprintf(&props, "        <p%d>${p%d}</p%d>\n", i, i+1, i)
		}
		fmt.Fprintf(&props, "        <p%d>9.0.5</p%d>\n", chain, chain)
		depNode := depFor(wrap(props.String(), "${p0}"))
		require.NotNil(t, depNode)
		assert.Nil(t, resolveMavenPropertyNode(depNode), "a chain deeper than the limit must not resolve")
	})

	t.Run("chain of exactly the depth limit still resolves", func(t *testing.T) {
		// p0..pLast where pLast is concrete. The concrete value is looked up on the
		// final (maxPropertyIndirectionDepth-th) iteration, so it resolves only if
		// the bound is not off-by-one in the too-aggressive direction (which would
		// drop a valid resolution and silently corrupt the dependency instead).
		last := maxPropertyIndirectionDepth - 1
		var props strings.Builder
		for i := 0; i < last; i++ {
			fmt.Fprintf(&props, "        <p%d>${p%d}</p%d>\n", i, i+1, i)
		}
		fmt.Fprintf(&props, "        <p%d>9.0.5</p%d>\n", last, last)
		depNode := depFor(wrap(props.String(), "${p0}"))
		require.NotNil(t, depNode)
		resolved := resolveMavenPropertyNode(depNode)
		require.NotNil(t, resolved, "a chain of exactly the depth limit must still resolve")
		assert.Equal(t, "9.0.5", resolved.Value)
	})
}

// resolveMavenPropertyNode must handle the variety of property names and value
// formatting found in real poms: bare and dotted names, a reference written with
// padding inside ${ }, and a property value padded with surrounding whitespace.
func Test_resolveMavenPropertyNode_NameAndWhitespaceVariants(t *testing.T) {
	engine := testutil.UnitTest(t)

	// pom builds a single-dependency pom whose version is versionRef and whose
	// <properties> defines propName with propValue.
	pom := func(propName, propValue, versionRef string) string {
		return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
			"<project>\n" +
			"    <properties>\n" +
			"        <" + propName + ">" + propValue + "</" + propName + ">\n" +
			"    </properties>\n" +
			"    <dependencies>\n" +
			"        <dependency>\n" +
			"            <groupId>org.cyclonedx</groupId>\n" +
			"            <artifactId>cyclonedx-core-java</artifactId>\n" +
			"            <version>" + versionRef + "</version>\n" +
			"        </dependency>\n" +
			"    </dependencies>\n" +
			"</project>\n"
	}

	tests := []struct {
		name       string
		propName   string
		propValue  string
		versionRef string
	}{
		{name: "bare name", propName: "cyclonedxversion", propValue: "9.0.5", versionRef: "${cyclonedxversion}"},
		{name: "dotted name", propName: "lib.cyclonedx-core-java.version", propValue: "9.0.5", versionRef: "${lib.cyclonedx-core-java.version}"},
		{name: "whitespace inside reference braces", propName: "foo.version", propValue: "9.0.5", versionRef: "${ foo.version }"},
		{name: "whitespace-padded property value", propName: "foo.version", propValue: "  9.0.5  ", versionRef: "${foo.version}"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			content := pom(tc.propName, tc.propValue, tc.versionRef)
			from := []string{"root@1.0.0", "org.cyclonedx:cyclonedx-core-java@9.0.5"}
			depNode := getDependencyNode(engine.GetLogger(), types.FilePath("pom.xml"), "maven", from, []byte(content), "")
			require.NotNil(t, depNode)

			resolved := resolveMavenPropertyNode(depNode)
			require.NotNil(t, resolved, "property reference should resolve to a node")
			assert.Equal(t, "9.0.5", resolved.Value, "resolved value should be trimmed to the concrete version")
		})
	}
}

// textAtRange must refuse every range it cannot read so the stale-edit guard
// never silently passes. These cover the refusal branches that fire when the
// file got shorter (fewer lines, or a now-shorter line) after a prior apply, in
// addition to the happy path.
func Test_textAtRange_RefusesUnreadableRanges(t *testing.T) {
	const content = "<x>\n            <version>9.0.5</version>\n</x>\n"
	mkRange := func(startLine, startChar, endLine, endChar int) types.Range {
		return types.Range{
			Start: types.Position{Line: startLine, Character: startChar},
			End:   types.Position{Line: endLine, Character: endChar},
		}
	}

	tests := []struct {
		name     string
		content  []byte
		r        types.Range
		wantOK   bool
		wantText string
	}{
		{name: "nil content", content: nil, r: mkRange(0, 0, 0, 3), wantOK: false},
		{name: "multi-line range", content: []byte(content), r: mkRange(0, 0, 1, 5), wantOK: false},
		{name: "negative start line", content: []byte(content), r: mkRange(-1, 0, -1, 1), wantOK: false},
		{name: "start line past end (file got shorter)", content: []byte("only one line\n"), r: mkRange(5, 0, 5, 3), wantOK: false},
		{name: "negative start char", content: []byte(content), r: mkRange(0, -1, 0, 2), wantOK: false},
		{name: "start char after end char", content: []byte(content), r: mkRange(0, 3, 0, 1), wantOK: false},
		{name: "end char past line length (line got shorter)", content: []byte("<x>\n<v>1</v>\n"), r: mkRange(0, 0, 0, 99), wantOK: false},
		{name: "valid single-line range", content: []byte(content), r: mkRange(0, 0, 0, 3), wantOK: true, wantText: "<x>"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			text, ok := textAtRange(tc.content, tc.r)
			assert.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				assert.Equal(t, tc.wantText, text)
			}
		})
	}
}

// applyMavenUpgradeQuickfix writes pom to a temp pom.xml, builds the maven upgrade
// quickfix for org.cyclonedx:cyclonedx-core-java 9.0.5 -> 11.0.1, applies the
// deferred edit and returns the resulting edits for that pom path.
func applyMavenUpgradeQuickfix(t *testing.T, pom string) []types.TextEdit {
	t.Helper()
	engine := testutil.UnitTest(t)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingEnableSnykOssQuickFixActions), true)

	dir := t.TempDir()
	pomPath := filepath.Join(dir, "pom.xml")
	require.NoError(t, os.WriteFile(pomPath, []byte(pom), 0600))

	from := []string{"root@1.0.0", "org.cyclonedx:cyclonedx-core-java@9.0.5"}
	depNode := getDependencyNode(engine.GetLogger(), types.FilePath(pomPath), "maven", from, []byte(pom), types.FilePath(dir))
	require.NotNil(t, depNode)

	issue := mavenTestIssue()
	issue.From = from
	issue.UpgradePath = []any{"false", "org.cyclonedx:cyclonedx-core-java@11.0.1"}

	snykIssue := toIssue(engine, defaultResolver(t, engine), types.FilePath(dir), types.FilePath(pomPath), issue,
		&scanResult{}, nil, depNode, getLearnMock(t), error_reporting.NewTestErrorReporter(engine), "", nil)
	quickFix := findUpgradeAction(t, snykIssue.CodeActions)
	edit := (*quickFix.GetDeferredEdit())()
	return edit.Changes[pomPath]
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
