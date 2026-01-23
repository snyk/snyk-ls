/*
 * © 2026 Snyk Limited All rights reserved.
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

package directory_check

// UsedDirectory represents a directory used by Snyk (for CLI, config, cache, or temp files)
type UsedDirectory struct {
	PathWanted    string `json:"pathWanted"`
	Purpose       string `json:"purpose"`
	MayContainCLI bool   `json:"mayContainCLI"`
}

// DirectoryCheckResult represents the result of checking a directory
type DirectoryCheckResult struct {
	PathWanted    string       `json:"pathWanted"`
	Purpose       string       `json:"purpose"`
	MayContainCLI bool         `json:"mayContainCLI"`
	PathFound     string       `json:"pathFound"`
	IsWritable    bool         `json:"isWritable"`
	Permissions   string       `json:"permissions,omitempty"`
	BinariesFound []BinaryInfo `json:"binariesFound,omitempty"`
	Error         string       `json:"error,omitempty"`
}

// BinaryInfo represents information about a CLI binary found in a directory
type BinaryInfo struct {
	Name        string `json:"name"`
	Permissions string `json:"permissions"`
}

// DiagnosticsResult represents the complete result of directory diagnostics
type DiagnosticsResult struct {
	CurrentUser      string                 `json:"currentUser"`
	DirectoryResults []DirectoryCheckResult `json:"directoryResults"`
}
