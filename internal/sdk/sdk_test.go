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

package sdk

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetPath_EmptyExtension_ReturnsCurrentPath(t *testing.T) {
	const current = "a" + string(os.PathListSeparator) + "b"
	t.Setenv(pathEnvVarName, current)

	assert.Equal(t, current, getPath("", true))
	assert.Equal(t, current, getPath("", false))
}

func TestGetPath_EmptyCurrentPath_ReturnsExtension(t *testing.T) {
	t.Setenv(pathEnvVarName, "")
	assert.Equal(t, "x", getPath("x", true))
	assert.Equal(t, "x", getPath("x", false))
}

func TestGetPath_Prepend_DedupesAndReprioritizes(t *testing.T) {
	sep := string(os.PathListSeparator)
	// current contains "b"; when prepending "b" it should move to the front
	current := strings.Join([]string{"a", "b", "c"}, sep)
	t.Setenv(pathEnvVarName, current)

	expected := strings.Join([]string{"b", "a", "c"}, sep)
	assert.Equal(t, expected, getPath("b", true))
}

func TestGetPath_Append_DoesNotDuplicateExistingEntry(t *testing.T) {
	sep := string(os.PathListSeparator)
	current := strings.Join([]string{"a", "b", "c"}, sep)
	t.Setenv(pathEnvVarName, current)

	assert.Equal(t, current, getPath("b", false))
}

func TestGetPath_ExtensionWithMultipleEntries_PrependsAllAndDedupes(t *testing.T) {
	sep := string(os.PathListSeparator)
	current := strings.Join([]string{"a", "b", "c"}, sep)
	t.Setenv(pathEnvVarName, current)

	ext := strings.Join([]string{"x", "b"}, sep)
	expected := strings.Join([]string{"x", "b", "a", "c"}, sep)
	assert.Equal(t, expected, getPath(ext, true))
}
