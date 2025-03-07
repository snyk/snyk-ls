/*
 * © 2023 Snyk Limited
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

package parser

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func createTestFile(t *testing.T) *os.File {
	t.Helper()
	dir := types.FilePath(t.TempDir())
	file := testsupport.CreateTempFile(t, string(dir))
	fileContent :=
		`<html>
			<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>
			<script src="https://stackpath.bootstrapcdn.com/bootstrap/3.1.7/js/bootstrap.min.js"></script>
			<script src="https://yastatic.net/lodash/4.10.0/lodash.core.min.js"></script>
			<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.min.js"></script>
			<script src="https://unpkg.com/react@16.7.0/umd/react.production.min.js"></script>
			<script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
			<script src="https://ajax.aspnetcdn.com/ajax/jquery/jquery-1.9.0.min.js"></script>
		</html>`
	_, err := file.WriteString(fileContent)
	assert.NoError(t, err)
	err = file.Close()
	assert.NoError(t, err)
	return file
}

func TestHtmlParser_Parse_FindsDependencies(t *testing.T) {
	c := testutil.UnitTest(t)
	p := NewHTMLParser(c)
	file := createTestFile(t)

	dependencies, err := p.Parse(types.FilePath(file.Name()))

	assert.NoError(t, err)
	assert.Len(t, dependencies, 7)
}

func TestHtmlParser_parses_maxcdn(t *testing.T) {
	c := testutil.UnitTest(t)
	h := NewHTMLParser(c).(*htmlParser)
	file := createTestFile(t)

	dependencies, err := h.Parse(types.FilePath(file.Name()))
	assert.NoError(t, err)

	assert.Equal(t, "bootstrap", dependencies[0].ArtifactID)
	assert.Equal(t, "3.3.7", dependencies[0].Version)
}
func TestHtmlParser_parses_stackpath(t *testing.T) {
	c := testutil.UnitTest(t)
	h := NewHTMLParser(c).(*htmlParser)
	file := createTestFile(t)

	dependencies, err := h.Parse(types.FilePath(file.Name()))
	assert.NoError(t, err)

	assert.Equal(t, "bootstrap", dependencies[1].ArtifactID)
	assert.Equal(t, "3.1.7", dependencies[1].Version)
}
func TestHtmlParser_parses_yastatic(t *testing.T) {
	c := testutil.UnitTest(t)
	h := NewHTMLParser(c).(*htmlParser)
	file := createTestFile(t)

	dependencies, err := h.Parse(types.FilePath(file.Name()))
	assert.NoError(t, err)

	assert.Equal(t, "lodash", dependencies[2].ArtifactID)
	assert.Equal(t, "4.10.0", dependencies[2].Version)
}
func TestHtmlParser_parses_jsdelivrnet(t *testing.T) {
	c := testutil.UnitTest(t)
	h := NewHTMLParser(c).(*htmlParser)
	file := createTestFile(t)

	dependencies, err := h.Parse(types.FilePath(file.Name()))
	assert.NoError(t, err)

	assert.Equal(t, "bootstrap", dependencies[3].ArtifactID)
	assert.Equal(t, "5.2.3", dependencies[3].Version)
}
func TestHtmlParser_parses_unpkg(t *testing.T) {
	c := testutil.UnitTest(t)
	h := NewHTMLParser(c).(*htmlParser)
	file := createTestFile(t)

	dependencies, err := h.Parse(types.FilePath(file.Name()))
	assert.NoError(t, err)

	assert.Equal(t, "react", dependencies[4].ArtifactID)
	assert.Equal(t, "16.7.0", dependencies[4].Version)
}
func TestHtmlParser_parses_jquery(t *testing.T) {
	c := testutil.UnitTest(t)
	h := NewHTMLParser(c).(*htmlParser)
	file := createTestFile(t)

	dependencies, err := h.Parse(types.FilePath(file.Name()))
	assert.NoError(t, err)

	assert.Equal(t, "jquery", dependencies[5].ArtifactID)
	assert.Equal(t, "3.7.0", dependencies[5].Version)
}
func TestHtmlParser_parses_aspnetcdn(t *testing.T) {
	c := testutil.UnitTest(t)
	h := NewHTMLParser(c).(*htmlParser)
	file := createTestFile(t)

	dependencies, err := h.Parse(types.FilePath(file.Name()))
	assert.NoError(t, err)

	assert.Equal(t, "jquery", dependencies[6].ArtifactID)
	assert.Equal(t, "1.9.0", dependencies[6].Version)
}
