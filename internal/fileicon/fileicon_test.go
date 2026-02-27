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

package fileicon_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/fileicon"
)

func TestGetOSFileIcon_NoExtension_ReturnsGenericSVG(t *testing.T) {
	icon := fileicon.GetOSFileIcon("filewithnoextension")
	assert.NotEmpty(t, icon)
	assert.Contains(t, icon, "<svg")
}

func TestGetOSFileIcon_KnownExtension_ReturnsValidHTMLFragment(t *testing.T) {
	icon := fileicon.GetOSFileIcon("/some/path/file.ts")
	assert.NotEmpty(t, icon)
	assert.True(t,
		strings.Contains(icon, "<svg") || strings.Contains(icon, "<img"),
		"expected <svg or <img element, got: %s", icon,
	)
}

func TestGetOSFileIcon_CachesResultByExtension(t *testing.T) {
	fileicon.ResetIconCache()

	icon1 := fileicon.GetOSFileIcon("/path/a/file.go")
	icon2 := fileicon.GetOSFileIcon("/other/path/main.go")

	assert.Equal(t, icon1, icon2, "same extension should return identical cached result")
}

func TestGetOSFileIcon_MultipleExtensions_NoPanicAndNonEmpty(t *testing.T) {
	extensions := []string{".ts", ".py", ".java", ".html", ".css", ".go", ".rs", ".rb", ".json", ".xml"}
	for _, ext := range extensions {
		icon := fileicon.GetOSFileIcon("/path/file" + ext)
		assert.NotEmpty(t, icon, "expected non-empty icon for %s", ext)
	}
}

func TestGetOSFileIcon_CaseInsensitiveExtension(t *testing.T) {
	fileicon.ResetIconCache()

	lower := fileicon.GetOSFileIcon("/path/file.go")
	upper := fileicon.GetOSFileIcon("/path/FILE.GO")

	assert.Equal(t, lower, upper, ".go and .GO should yield the same cached icon")
}
