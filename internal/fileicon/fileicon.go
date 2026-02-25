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

// Package fileicon provides file icon resolution for tree view nodes.
// Package manager icons for OSS nodes are inlined as SVG constants.
// For all other file types the icon is fetched from the host OS at render time
// and cached in memory (per extension) for the lifetime of the process.
package fileicon

import (
	"path/filepath"
	"strings"

	"github.com/erni27/imcache"
)

// genericFileSVG is the final fallback used when the OS cannot provide an icon.
const genericFileSVG = `<svg width="16" height="16" viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg" fill="none"><path d="M20.414,2H5V30H27V8.586ZM7,28V4H19v6h6V28Z" fill="#888"/></svg>`

// osIconCache stores resolved OS icons keyed by lowercase file extension.
// No expiry is set because file-type icons do not change during the process lifetime.
var osIconCache = imcache.New[string, string]()

// GetOSFileIcon returns an HTML fragment (inline SVG or <img> tag) representing
// the OS-assigned icon for the file identified by filePath.
// Results are cached per lowercase file extension for the lifetime of the process.
// Returns the generic file SVG when the extension is empty or OS lookup fails.
func GetOSFileIcon(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == "" {
		return genericFileSVG
	}

	if cached, ok := osIconCache.Get(ext); ok {
		return cached
	}

	icon := fetchOSFileIcon(ext)
	if icon == "" {
		icon = genericFileSVG
	}

	osIconCache.Set(ext, icon, imcache.WithNoExpiration())

	return icon
}
