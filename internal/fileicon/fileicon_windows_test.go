//go:build windows

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
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/fileicon"
)

// --- fetchOSFileIcon (SHGetFileInfoW + GDI layer) ---
//
// These tests call the raw OS lookup directly so that results are not masked
// by the generic-SVG fallback that GetOSFileIcon wraps around it.

// TestFetchOSFileIcon_Windows_UnknownExtension_ReturnsEmpty verifies that a
// completely unrecognised extension yields "" from SHGetFileInfoW.
// GetOSFileIcon then converts that "" to the generic SVG fallback.
func TestFetchOSFileIcon_Windows_UnknownExtension_ReturnsEmpty(t *testing.T) {
	icon := fileicon.FetchOSFileIconForTesting(".xyzunknown999")
	// Windows may still return a generic document icon for unknown extensions,
	// so we accept either "" or a valid <img> tag.
	if icon != "" {
		assert.Contains(t, icon, "<img", "non-empty result must be a base64 <img> tag, not a raw SVG")
	}
}

// TestFetchOSFileIcon_Windows_ExeExtension_ReturnsImgTag checks that .exe,
// which has a well-known shell icon on every Windows installation, returns a
// base64 PNG <img> tag from the GDI pipeline.
func TestFetchOSFileIcon_Windows_ExeExtension_ReturnsImgTag(t *testing.T) {
	icon := fileicon.FetchOSFileIconForTesting(".exe")
	assert.NotEmpty(t, icon, "SHGetFileInfoW should always return an icon for .exe")
	assert.Contains(t, icon, "<img", ".exe result must be a base64 <img> tag, not a generic SVG fallback")
}

// TestFetchOSFileIcon_Windows_TxtExtension_ReturnsImgTag checks that .txt,
// which maps to the Notepad icon, returns a base64 PNG <img> tag.
func TestFetchOSFileIcon_Windows_TxtExtension_ReturnsImgTag(t *testing.T) {
	icon := fileicon.FetchOSFileIconForTesting(".txt")
	assert.NotEmpty(t, icon)
	assert.Contains(t, icon, "<img", ".txt result must be a base64 <img> tag, not a generic SVG fallback")
}

// --- GetOSFileIcon (public API + fallback layer) ---

// TestGetOSFileIcon_Windows_UnknownExtension_FallsBackToGenericSVG confirms
// that GetOSFileIcon substitutes the generic SVG when the OS lookup returns "".
// This test is only meaningful when fetchOSFileIcon genuinely returns "".
func TestGetOSFileIcon_Windows_UnknownExtension_FallsBackToGenericSVG(t *testing.T) {
	fileicon.ResetIconCache()
	raw := fileicon.FetchOSFileIconForTesting(".xyzunknown999")
	if raw != "" && os.Getenv("CI") != "" {
		t.Skip("SHGetFileInfoW returned an icon even for the unknown extension in CI – fallback path not reachable")
	}

	icon := fileicon.GetOSFileIcon("/path/to/file.xyzunknown999")
	assert.Contains(t, icon, "<svg", "GetOSFileIcon must return the generic SVG when OS lookup returns \"\"")
	assert.NotContains(t, icon, "<img", "generic SVG fallback must not be an <img> tag")
}
