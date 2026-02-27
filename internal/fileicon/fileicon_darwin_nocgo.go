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

package fileicon

// fetchOSFileIcon returns "" when CGo is disabled, causing the caller to fall
// back to the generic file SVG. The NSWorkspace API required to retrieve
// file-type icons is Objective-C only and not reachable without CGo.
func fetchOSFileIcon(_ string) string {
	return ""
}
