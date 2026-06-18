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
	"os"
	"path/filepath"
	"strings"
	"testing"

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

func TestCreateHierarchicalDependencyTree(t *testing.T) {
	engine := testutil.UnitTest(t)
	var testPath, _ = filepath.Abs("testdata/maven-goof/sub/pom.xml")
	var testContent, _ = os.ReadFile(testPath)
	parser := Parser{logger: engine.GetLogger()}
	tree := parser.Parse(string(testContent), types.FilePath(testPath))

	assert.NotNilf(t, tree.ParentTree, "Should have returned a Parent tree")

	assert.Len(t, tree.ParentTree.Root.Children, 2)
}
