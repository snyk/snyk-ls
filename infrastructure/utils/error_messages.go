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

package utils

const (
	ErrSnykCodeNotEnabled = "Snyk Code is not enabled for this organization"
	ErrNoReferenceBranch  = "must specify reference for delta scans"
	ErrNoRepo             = "repository does not exist"
)

// ErrorMetadata contains metadata about how to handle specific errors
type ErrorMetadata struct {
	ShowNotification bool
	TreeRootSuffix   string
}

// ErrorConfig maps error messages to their metadata
var ErrorConfig = map[string]ErrorMetadata{
	ErrSnykCodeNotEnabled: {
		ShowNotification: false,
		TreeRootSuffix:   "(disabled at Snyk)",
	},
	ErrNoReferenceBranch: {
		ShowNotification: false,
		TreeRootSuffix:   "(no reference branch)",
	},
	ErrNoRepo: {
		ShowNotification: false,
		TreeRootSuffix:   "(repository not found)",
	},
}
