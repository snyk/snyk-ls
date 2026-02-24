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

package fileicon

import (
	"encoding/base64"
	"fmt"
	"mime"
	"os"
	"path/filepath"
	"strings"
)

// iconSearchDirs contains the directories searched for MIME-type icon files,
// ordered by preference (hicolor theme first, then generic fallbacks).
var iconSearchDirs = []string{
	"/usr/share/icons/hicolor/16x16/mimetypes",
	"/usr/share/icons/gnome/16x16/mimetypes",
	"/usr/share/icons/Adwaita/16x16/mimetypes",
	"/usr/share/pixmaps",
}

// fetchOSFileIcon looks up the MIME type for the extension, then searches known
// icon theme directories for a matching PNG or SVG.
func fetchOSFileIcon(ext string) string {
	mimeType := mime.TypeByExtension(ext)
	if mimeType == "" {
		return ""
	}

	// Strip MIME parameters (e.g. "; charset=utf-8").
	if i := strings.Index(mimeType, ";"); i >= 0 {
		mimeType = strings.TrimSpace(mimeType[:i])
	}

	// Freedesktop icon name convention: "text/html" → "text-html".
	iconName := strings.ReplaceAll(mimeType, "/", "-")

	for _, dir := range iconSearchDirs {
		for _, imgExt := range []string{".svg", ".png"} {
			iconPath := filepath.Join(dir, iconName+imgExt)
			data, err := os.ReadFile(iconPath)
			if err != nil {
				continue
			}
			if imgExt == ".svg" {
				return string(data)
			}
			encoded := base64.StdEncoding.EncodeToString(data)
			return fmt.Sprintf(`<img src="data:image/png;base64,%s" width="16" height="16"/>`, encoded)
		}
	}

	return ""
}
