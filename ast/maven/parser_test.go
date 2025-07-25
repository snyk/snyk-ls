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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestCreateDependencyTree(t *testing.T) {
	c := testutil.UnitTest(t)
	var testPath, _ = filepath.Abs("testdata/pom.xml")
	var testContent, _ = os.ReadFile(testPath)
	parser := Parser{logger: c.Logger()}
	tree := parser.Parse(string(testContent), types.FilePath(testPath))
	children := tree.Root.Children
	assert.Len(t, children, 2, "Should have extracted 2 deps from pom.xml")

	assert.Equal(t, 54, children[0].Line)
	assert.Equal(t, 15, children[0].StartChar)
	assert.Equal(t, 21, children[0].EndChar)

	assert.Equal(t, 59, children[1].Line)
	assert.Equal(t, 15, children[1].StartChar)
	assert.Equal(t, 21, children[1].EndChar)
}

func TestCreateHierarchicalDependencyTree(t *testing.T) {
	c := testutil.UnitTest(t)
	var testPath, _ = filepath.Abs("testdata/maven-goof/sub/pom.xml")
	var testContent, _ = os.ReadFile(testPath)
	parser := Parser{logger: c.Logger()}
	tree := parser.Parse(string(testContent), types.FilePath(testPath))

	assert.NotNilf(t, tree.ParentTree, "Should have returned a Parent tree")

	assert.Len(t, tree.ParentTree.Root.Children, 2)
}
