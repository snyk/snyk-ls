/*
 * © 2022 Snyk Limited All rights reserved.
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

package maven

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestCreateDependencyTree(t *testing.T) {
	engine := testutil.UnitTest(t)
	var testPath, _ = filepath.Abs("testdata/pom.xml")
	var testContent, _ = os.ReadFile(testPath)
	parser := Parser{logger: engine.GetLogger()}
	tree := parser.Parse(string(testContent), types.FilePath(testPath))
	children := tree.Root.Children
	assert.Len(t, children, 2, "Should have extracted 2 deps from pom.xml")

	lines := strings.Split(strings.ReplaceAll(string(testContent), "\r", ""), "\n")
	version := "2.14.1"

	expectedLineNumber := 54
	node := children[0]

	assert.Equal(t, expectedLineNumber, node.Line)
	index := strings.Index(lines[expectedLineNumber], version)
	assert.Equal(t, index, node.StartChar)
	assert.Equal(t, index+len(version), node.EndChar)

	expectedLineNumber = 59
	node = children[1]
	assert.Equal(t, expectedLineNumber, node.Line)
	index = strings.Index(lines[expectedLineNumber], version)
	assert.Equal(t, index, node.StartChar)
	assert.Equal(t, index+len(version), node.EndChar)
}

func TestParse_PopulatesProperties(t *testing.T) {
	engine := testutil.UnitTest(t)
	content := `<?xml version="1.0" encoding="UTF-8"?>
<project>
    <properties>
        <maven.compiler.source>11</maven.compiler.source>

        <!-- a comment between properties should not break parsing -->
        <lib.cyclonedx-core-java.version>9.0.5</lib.cyclonedx-core-java.version>
    </properties>
</project>
`
	parser := Parser{logger: engine.GetLogger()}
	tree := parser.Parse(content, types.FilePath("pom.xml"))

	require.NotNil(t, tree.Properties)

	node, ok := tree.Properties["lib.cyclonedx-core-java.version"]
	require.True(t, ok, "expected the property to be parsed into the tree")
	assert.Equal(t, "9.0.5", node.Value)

	lines := strings.Split(content, "\n")
	expectedLine := -1
	for i, l := range lines {
		if strings.Contains(l, "<lib.cyclonedx-core-java.version>") {
			expectedLine = i
		}
	}
	require.GreaterOrEqual(t, expectedLine, 0)

	startChar := strings.Index(lines[expectedLine], "9.0.5")
	assert.Equal(t, expectedLine, node.Line)
	assert.Equal(t, startChar, node.StartChar)
	assert.Equal(t, startChar+len("9.0.5"), node.EndChar)

	// a simple property is parsed too, and its position must be correct (guards
	// off-by-one regressions in newValueNode on the no-comment case).
	compiler, ok := tree.Properties["maven.compiler.source"]
	require.True(t, ok)
	assert.Equal(t, "11", compiler.Value)

	compilerLine := -1
	for i, l := range lines {
		if strings.Contains(l, "<maven.compiler.source>") {
			compilerLine = i
		}
	}
	require.GreaterOrEqual(t, compilerLine, 0)
	compilerStart := strings.Index(lines[compilerLine], "11")
	assert.Equal(t, compilerLine, compiler.Line)
	assert.Equal(t, compilerStart, compiler.StartChar)
	assert.Equal(t, compilerStart+len("11"), compiler.EndChar)
}

func TestParse_PropertiesEdgeCases(t *testing.T) {
	engine := testutil.UnitTest(t)
	parser := Parser{logger: engine.GetLogger()}

	tests := []struct {
		name    string
		content string
		// absentKey, when set, must NOT be present in tree.Properties.
		absentKey string
	}{
		{
			name: "empty properties block",
			content: `<?xml version="1.0" encoding="UTF-8"?>
<project>
    <properties></properties>
</project>
`,
		},
		{
			name: "no properties block",
			content: `<?xml version="1.0" encoding="UTF-8"?>
<project>
</project>
`,
		},
		{
			name: "whitespace-only value is skipped",
			content: `<?xml version="1.0" encoding="UTF-8"?>
<project>
    <properties>
        <foo>   </foo>
    </properties>
</project>
`,
			absentKey: "foo",
		},
		{
			// Empty value: scanPropertyValueSpan returns start==end (the end tag is
			// reached with no CharData), so the slice is empty and the property is
			// skipped without a panic or a bogus zero-length entry.
			name: "empty value element is skipped",
			content: `<?xml version="1.0" encoding="UTF-8"?>
<project>
    <properties>
        <empty.prop></empty.prop>
    </properties>
</project>
`,
			absentKey: "empty.prop",
		},
		{
			name: "self-closing value element is skipped",
			content: `<?xml version="1.0" encoding="UTF-8"?>
<project>
    <properties>
        <selfclosing.prop/>
    </properties>
</project>
`,
			absentKey: "selfclosing.prop",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree := parser.Parse(tc.content, types.FilePath("pom.xml"))
			// resolveMavenPropertyNode does a tree.Properties[name] lookup, so the
			// map must always be non-nil even when there are no properties.
			require.NotNil(t, tree.Properties, "Properties map must be non-nil")
			if tc.absentKey != "" {
				_, ok := tree.Properties[tc.absentKey]
				assert.False(t, ok, "whitespace-only property must not be registered")
			} else {
				assert.Empty(t, tree.Properties, "no properties should be registered")
			}
		})
	}
}

func TestParse_PropertyWithNestedElement_DoesNotMisregisterSiblings(t *testing.T) {
	engine := testutil.UnitTest(t)
	content := `<?xml version="1.0" encoding="UTF-8"?>
<project>
    <properties>
        <nested><inner>1</inner></nested>
        <plain.version>9.0.5</plain.version>
    </properties>
</project>
`
	parser := Parser{logger: engine.GetLogger()}
	tree := parser.Parse(content, types.FilePath("pom.xml"))

	require.NotNil(t, tree.Properties)

	// The sibling property after the nested one must still be parsed correctly,
	// and the nested child (<inner>) must NOT be registered as a top-level property.
	_, innerRegistered := tree.Properties["inner"]
	assert.False(t, innerRegistered, "nested child element must not be registered as a property")

	plain, ok := tree.Properties["plain.version"]
	require.True(t, ok, "sibling property after a nested-value property must still be parsed")
	assert.Equal(t, "9.0.5", plain.Value)

	lines := strings.Split(content, "\n")
	expectedLine := -1
	for i, l := range lines {
		if strings.Contains(l, "<plain.version>") {
			expectedLine = i
		}
	}
	require.GreaterOrEqual(t, expectedLine, 0)
	startChar := strings.Index(lines[expectedLine], "9.0.5")
	assert.Equal(t, expectedLine, plain.Line)
	assert.Equal(t, startChar, plain.StartChar)
	assert.Equal(t, startChar+len("9.0.5"), plain.EndChar)
}

func TestParse_ParentChainDepthCap_StopsAtLimit(t *testing.T) {
	engine := testutil.UnitTest(t)
	dir := t.TempDir()

	// Chain of distinct POMs p0 -> p1 -> ... each naming the next as parent, longer
	// than maxParentDepth. Distinct paths mean the visited-set never fires, so only
	// the depth cap can stop the walk — which is what we are testing.
	total := maxParentDepth + 5
	pomPath := func(i int) string { return filepath.Join(dir, fmt.Sprintf("p%d", i), "pom.xml") }
	for i := 0; i <= total; i++ {
		require.NoError(t, os.MkdirAll(filepath.Dir(pomPath(i)), 0755))
		content := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<project>\n</project>\n"
		if i < total {
			content = fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<project>\n    <parent>\n        <relativePath>../p%d/pom.xml</relativePath>\n    </parent>\n</project>\n", i+1)
		}
		require.NoError(t, os.WriteFile(pomPath(i), []byte(content), 0600))
	}

	p0, err := os.ReadFile(pomPath(0))
	require.NoError(t, err)
	parser := Parser{logger: engine.GetLogger()}
	tree := parser.Parse(string(p0), types.FilePath(pomPath(0)))

	// Walk the ParentTree chain; it must stop at exactly maxParentDepth parents even
	// though more parent POMs exist on disk.
	links := 0
	for tr := tree; tr.ParentTree != nil; tr = tr.ParentTree {
		links++
	}
	assert.Equal(t, maxParentDepth, links, "parent chain must stop at maxParentDepth")
}

func TestParse_ParentRelativePathIsDirectory_Skipped(t *testing.T) {
	testutil.UnitTest(t)
	dir := t.TempDir()
	childDir := filepath.Join(dir, "child")
	require.NoError(t, os.MkdirAll(childDir, 0755))
	// relativePath resolves to a directory, not a regular file.
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "parent"), 0755))

	childPath := filepath.Join(childDir, "pom.xml")
	content := `<?xml version="1.0" encoding="UTF-8"?>
<project>
    <parent>
        <relativePath>../parent</relativePath>
    </parent>
</project>
`
	require.NoError(t, os.WriteFile(childPath, []byte(content), 0600))

	// Capture logs and assert the IsRegular guard is specifically what skipped the
	// directory. Asserting only a nil ParentTree would be vacuous: with the guard
	// removed, the downstream os.ReadFile(dir) also errors and bails, yielding the
	// same nil result. The distinct log message ("not a regular file" vs the
	// ReadFile error's "Couldn't read Parent file") isolates the intended branch.
	var buf bytes.Buffer
	logger := zerolog.New(&buf)
	parser := Parser{logger: &logger}
	tree := parser.Parse(content, types.FilePath(childPath))

	assert.Nil(t, tree.ParentTree, "a non-regular parent path (directory) must be skipped")
	assert.Contains(t, buf.String(), "not a regular file",
		"the IsRegular guard must be what skips the directory, not the ReadFile error path")
}

func TestParse_ParentExceedsSizeCap_Skipped(t *testing.T) {
	engine := testutil.UnitTest(t)
	dir := t.TempDir()
	childDir := filepath.Join(dir, "child")
	parentDir := filepath.Join(dir, "parent")
	require.NoError(t, os.MkdirAll(childDir, 0755))
	require.NoError(t, os.MkdirAll(parentDir, 0755))

	// A parent POM just over the size cap. The size check happens before the file is
	// read or parsed, so the content does not need to be valid XML.
	parentPath := filepath.Join(parentDir, "pom.xml")
	require.NoError(t, os.WriteFile(parentPath, make([]byte, maxParentPOMSize+1), 0600))

	childPath := filepath.Join(childDir, "pom.xml")
	content := `<?xml version="1.0" encoding="UTF-8"?>
<project>
    <parent>
        <relativePath>../parent/pom.xml</relativePath>
    </parent>
</project>
`
	require.NoError(t, os.WriteFile(childPath, []byte(content), 0600))

	parser := Parser{logger: engine.GetLogger()}
	tree := parser.Parse(content, types.FilePath(childPath))
	assert.Nil(t, tree.ParentTree, "a parent POM over the size cap must be skipped")
}

func TestParse_CyclicParentReference_DoesNotRecurseInfinitely(t *testing.T) {
	engine := testutil.UnitTest(t)
	dir := t.TempDir()

	// Two POMs that name each other as parent.
	pomA := filepath.Join(dir, "a", "pom.xml")
	pomB := filepath.Join(dir, "b", "pom.xml")
	require.NoError(t, os.MkdirAll(filepath.Dir(pomA), 0755))
	require.NoError(t, os.MkdirAll(filepath.Dir(pomB), 0755))

	contentA := `<?xml version="1.0" encoding="UTF-8"?>
<project>
    <parent>
        <relativePath>../b/pom.xml</relativePath>
    </parent>
</project>
`
	contentB := `<?xml version="1.0" encoding="UTF-8"?>
<project>
    <parent>
        <relativePath>../a/pom.xml</relativePath>
    </parent>
</project>
`
	require.NoError(t, os.WriteFile(pomA, []byte(contentA), 0600))
	require.NoError(t, os.WriteFile(pomB, []byte(contentB), 0600))

	parser := Parser{logger: engine.GetLogger()}
	// Must terminate; the cycle is broken by the visited-set rather than overflowing the stack.
	tree := parser.Parse(contentA, types.FilePath(pomA))

	require.NotNil(t, tree.ParentTree, "A's parent (B) should be parsed once")
	// B points back to A, but A is already in the visited set, so the chain stops here.
	assert.Nil(t, tree.ParentTree.ParentTree, "cycle back to A should be refused")
}

func TestParse_ParentOutsideWorkspaceRoot_Skipped(t *testing.T) {
	testutil.UnitTest(t)
	base := t.TempDir()
	root := filepath.Join(base, "workspace")
	childDir := filepath.Join(root, "module")
	outsideDir := filepath.Join(base, "outside")
	require.NoError(t, os.MkdirAll(childDir, 0755))
	require.NoError(t, os.MkdirAll(outsideDir, 0755))

	// A real parent POM living outside the workspace root (e.g. a sensitive file a
	// crafted relativePath points at). It is a valid POM, so only the containment
	// guard — not a parse/stat error — can stop the walk.
	outsidePath := filepath.Join(outsideDir, "pom.xml")
	require.NoError(t, os.WriteFile(outsidePath, []byte("<?xml version=\"1.0\"?>\n<project></project>\n"), 0600))

	childPath := filepath.Join(childDir, "pom.xml")
	// ../../outside/pom.xml climbs out of the workspace root.
	content := `<?xml version="1.0" encoding="UTF-8"?>
<project>
    <parent>
        <relativePath>../../outside/pom.xml</relativePath>
    </parent>
</project>
`
	require.NoError(t, os.WriteFile(childPath, []byte(content), 0600))

	var buf bytes.Buffer
	logger := zerolog.New(&buf)
	parser := New(&logger, types.FilePath(root))
	tree := parser.Parse(content, types.FilePath(childPath))

	assert.Nil(t, tree.ParentTree, "a parent POM resolving outside the workspace root must be skipped")
	assert.Contains(t, buf.String(), "outside the workspace root",
		"the containment guard must be what skips the parent, not a read/stat error")
}

func TestParse_ParentInsideWorkspaceRoot_StillFollowed(t *testing.T) {
	testutil.UnitTest(t)
	root := t.TempDir()
	childDir := filepath.Join(root, "module")
	parentDir := filepath.Join(root, "parent")
	require.NoError(t, os.MkdirAll(childDir, 0755))
	require.NoError(t, os.MkdirAll(parentDir, 0755))

	parentPath := filepath.Join(parentDir, "pom.xml")
	require.NoError(t, os.WriteFile(parentPath, []byte("<?xml version=\"1.0\"?>\n<project></project>\n"), 0600))

	childPath := filepath.Join(childDir, "pom.xml")
	content := `<?xml version="1.0" encoding="UTF-8"?>
<project>
    <parent>
        <relativePath>../parent/pom.xml</relativePath>
    </parent>
</project>
`
	require.NoError(t, os.WriteFile(childPath, []byte(content), 0600))

	var buf bytes.Buffer
	logger := zerolog.New(&buf)
	parser := New(&logger, types.FilePath(root))
	tree := parser.Parse(content, types.FilePath(childPath))

	// The guard must not block a legitimate parent that stays within the workspace.
	require.NotNil(t, tree.ParentTree, "a parent POM inside the workspace root must still be followed")
	// Assert the accept-branch was actually taken, not that the guard was bypassed:
	// the rejection warning must be absent for an in-workspace parent.
	assert.NotContains(t, buf.String(), "outside the workspace root",
		"an in-workspace parent must not trip the containment guard")
}

func TestParse_ParentSymlinkEscapesWorkspaceRoot_Skipped(t *testing.T) {
	testutil.UnitTest(t)
	base := t.TempDir()
	root := filepath.Join(base, "workspace")
	childDir := filepath.Join(root, "module")
	outsideDir := filepath.Join(base, "outside")
	require.NoError(t, os.MkdirAll(childDir, 0755))
	require.NoError(t, os.MkdirAll(outsideDir, 0755))

	// A real parent POM outside the workspace root.
	outsidePath := filepath.Join(outsideDir, "pom.xml")
	require.NoError(t, os.WriteFile(outsidePath, []byte("<?xml version=\"1.0\"?>\n<project></project>\n"), 0600))

	// A symlink that lives INSIDE the workspace root but points at the out-of-root
	// directory. A purely lexical containment check would accept <root>/module/link/pom.xml
	// because the string is in-root; the parser must resolve the symlink and refuse it.
	link := filepath.Join(childDir, "link")
	if err := os.Symlink(outsideDir, link); err != nil {
		t.Skipf("symlinks unsupported on this platform: %v", err)
	}

	childPath := filepath.Join(childDir, "pom.xml")
	content := `<?xml version="1.0" encoding="UTF-8"?>
<project>
    <parent>
        <relativePath>link/pom.xml</relativePath>
    </parent>
</project>
`
	require.NoError(t, os.WriteFile(childPath, []byte(content), 0600))

	var buf bytes.Buffer
	logger := zerolog.New(&buf)
	parser := New(&logger, types.FilePath(root))
	tree := parser.Parse(content, types.FilePath(childPath))

	assert.Nil(t, tree.ParentTree, "a parent reached via an in-root symlink that escapes the workspace must be skipped")
	assert.Contains(t, buf.String(), "outside the workspace root",
		"the containment guard must resolve the symlink and refuse the out-of-root target")
}

func TestParse_CyclicParentViaSymlink_DetectedByCanonicalPath(t *testing.T) {
	engine := testutil.UnitTest(t)
	dir := t.TempDir()

	// A symlink pointing back at the POM's own directory, so the parent reference
	// resolves to the POM itself through a lexically different path.
	link := filepath.Join(dir, "self")
	if err := os.Symlink(dir, link); err != nil {
		t.Skipf("symlinks unsupported on this platform: %v", err)
	}

	// relativePath self/pom.xml differs lexically from pom.xml but resolves to the
	// same real file. A visited-set keyed on filepath.Abs alone treats them as
	// different files and re-parses the parent up to maxParentDepth; only a
	// symlink-resolved (canonical) visited-set detects the cycle immediately.
	pomPath := filepath.Join(dir, "pom.xml")
	content := `<?xml version="1.0" encoding="UTF-8"?>
<project>
    <parent>
        <relativePath>self/pom.xml</relativePath>
    </parent>
</project>
`
	require.NoError(t, os.WriteFile(pomPath, []byte(content), 0600))

	parser := Parser{logger: engine.GetLogger()}
	tree := parser.Parse(content, types.FilePath(pomPath))

	assert.Nil(t, tree.ParentTree,
		"a parent reached via a symlink back to the same real POM must be detected as a cycle by the canonical visited-set, not re-parsed")
}

func TestCreateHierarchicalDependencyTree(t *testing.T) {
	engine := testutil.UnitTest(t)
	var testPath, _ = filepath.Abs("testdata/maven-goof/sub/pom.xml")
	var testContent, _ = os.ReadFile(testPath)
	parser := Parser{logger: engine.GetLogger()}
	tree := parser.Parse(string(testContent), types.FilePath(testPath))

	assert.NotNilf(t, tree.ParentTree, "Should have returned a Parent tree")

	assert.Len(t, tree.ParentTree.Root.Children, 2)
}
