//go:build linux

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

// --- fetchOSFileIcon (MIME + icon-theme layer) ---
//
// These tests call the raw OS lookup directly so that results are not masked
// by the generic-SVG fallback that GetOSFileIcon wraps around it.

// TestFetchOSFileIcon_Linux_UnknownExtension_ReturnsEmpty verifies that an
// extension with no MIME mapping yields "" from the lookup layer.
// GetOSFileIcon then converts that "" to the generic SVG fallback.
func TestFetchOSFileIcon_Linux_UnknownExtension_ReturnsEmpty(t *testing.T) {
	icon := fileicon.FetchOSFileIconForTesting(".xyzunknown999")
	assert.Empty(t, icon, "fetchOSFileIcon should return \"\" for an extension with no MIME type")
}

// TestFetchOSFileIcon_Linux_KnownMimeExtension_ReturnsIconOrEmpty checks that
// a well-known MIME type either resolves to an icon file from the installed
// theme or returns "" on minimal systems without icon themes.  The test skips
// if no theme icons are installed so it never produces a false-positive
// generic-SVG result.
func TestFetchOSFileIcon_Linux_KnownMimeExtension_ReturnsIconOrEmpty(t *testing.T) {
	// text/html is universally registered; its icon is text-html in hicolor themes.
	icon := fileicon.FetchOSFileIconForTesting(".html")
	if icon == "" && os.Getenv("CI") != "" {
		t.Skip("no Freedesktop icon theme installed in headless CI – skipping")
	}
	// When found, must be raw SVG content or a base64 <img> tag – never the generic fallback.
	assert.NotContains(t, icon, `viewBox="0 0 32 32"`, "icon theme result must not be the generic file SVG")
}

// --- GetOSFileIcon (public API + fallback layer) ---

// TestGetOSFileIcon_Linux_UnknownExtension_FallsBackToGenericSVG confirms that
// GetOSFileIcon substitutes the generic SVG when fetchOSFileIcon returns "".
func TestGetOSFileIcon_Linux_UnknownExtension_FallsBackToGenericSVG(t *testing.T) {
	fileicon.ResetIconCache()
	// Guarantee fetchOSFileIcon will return "" by using a nonsense extension.
	raw := fileicon.FetchOSFileIconForTesting(".xyzunknown999")
	assert.Empty(t, raw, "precondition: fetchOSFileIcon must return \"\" for the fallback path to be exercised")

	icon := fileicon.GetOSFileIcon("/path/to/file.xyzunknown999")
	assert.Contains(t, icon, "<svg", "GetOSFileIcon must return the generic SVG when the OS lookup returns \"\"")
	assert.NotContains(t, icon, "<img", "generic SVG fallback must not be an <img> tag")
}
