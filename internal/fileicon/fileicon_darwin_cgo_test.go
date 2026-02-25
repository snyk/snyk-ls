//go:build darwin && cgo

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
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/fileicon"
)

// NSWorkspace.iconForFileType: always returns at least a generic document icon,
// so fetchOSFileIcon must return a non-empty <img> tag for any extension.

func TestFetchOSFileIcon_Darwin_Cgo_KnownExtension_ReturnsImgTag(t *testing.T) {
	icon := fileicon.FetchOSFileIconForTesting(".png")
	require.NotEmpty(t, icon)
	assert.Contains(t, icon, "<img", "CGo path must return a base64 <img> tag for a known extension")
	assert.NotContains(t, icon, "<svg", "CGo path must not return the generic SVG fallback")
}

func TestFetchOSFileIcon_Darwin_Cgo_SourceFile_ReturnsImgTag(t *testing.T) {
	// .go has no dedicated macOS icon; NSWorkspace returns a generic document icon.
	icon := fileicon.FetchOSFileIconForTesting(".go")
	require.NotEmpty(t, icon)
	assert.Contains(t, icon, "<img", "CGo path must return a base64 <img> tag even for unregistered extensions")
}

func TestGetOSFileIcon_Darwin_Cgo_ReturnsImgTagNotGenericSVG(t *testing.T) {
	fileicon.ResetIconCache()
	icon := fileicon.GetOSFileIcon("/path/to/main.go")
	assert.Contains(t, icon, "<img", "with CGo enabled GetOSFileIcon should return an OS <img> icon, not the generic SVG")
}
