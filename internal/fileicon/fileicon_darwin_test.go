//go:build darwin && !cgo

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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/fileicon"
)

// Without CGo the OS-integration layer is not available; fetchOSFileIcon always
// returns "" and GetOSFileIcon falls back to the generic file SVG.

func TestFetchOSFileIcon_Darwin_NoCgo_AlwaysReturnsEmpty(t *testing.T) {
	assert.Empty(t, fileicon.FetchOSFileIconForTesting(".go"))
	assert.Empty(t, fileicon.FetchOSFileIconForTesting(".png"))
	assert.Empty(t, fileicon.FetchOSFileIconForTesting(".txt"))
}

func TestGetOSFileIcon_Darwin_NoCgo_FallsBackToGenericSVG(t *testing.T) {
	fileicon.ResetIconCache()

	for _, ext := range []string{".go", ".png", ".txt", ".json"} {
		icon := fileicon.GetOSFileIcon("/path/to/file" + ext)
		assert.Contains(t, icon, "<svg", "expected generic SVG fallback for %s (no CGo)", ext)
		assert.NotContains(t, icon, "<img", "must not return <img> without CGo")
	}
}
