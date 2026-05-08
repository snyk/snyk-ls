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
	// ErrSnykCodeNotEnabledForFolder is when Code is turned off for this workspace folder in the IDE / config (not org SAST).
	ErrSnykCodeNotEnabledForFolder = "Snyk Code is not enabled for this workspace folder"
	// ErrSnykSecretsNotEnabled is when Secrets is not available for the organization (e.g. feature flag).
	ErrSnykSecretsNotEnabled = "Snyk Secrets is not enabled for this organization"
	// ErrSnykSecretsNotEnabledForFolder is when Secrets is turned off for this workspace folder in the IDE / config.
	ErrSnykSecretsNotEnabledForFolder = "Snyk Secrets is not enabled for this workspace folder"
	// ErrSnykIacNotEnabledForFolder is when IaC is turned off for this workspace folder in the IDE / config.
	ErrSnykIacNotEnabledForFolder = "Snyk IaC is not enabled for this workspace folder"
	// ErrSnykOssNotEnabledForFolder is when Open Source is turned off for this workspace folder in the IDE / config.
	ErrSnykOssNotEnabledForFolder = "Snyk Open Source is not enabled for this workspace folder"
	ErrSastSettingsNotAvailable   = "SAST settings not available"
	ErrNoReferenceBranch          = "must specify reference for delta scans"
	ErrNoRepo                     = "repository does not exist"
	// ErrFolderConfigNotInContext is returned when FolderConfig is missing from the scan context (configuration bug).
	ErrFolderConfigNotInContext = "FolderConfig not found in context"
	// ErrOssScanPathUnsupported is when pathToScan is not a supported manifest, lockfile, or directory for OSS scanning.
	ErrOssScanPathUnsupported = "Open Source scan path is not a supported file/directory"
	// ErrIacScanPathUnsupported is when pathToScan is not a supported Terraform, YAML, JSON, or related IaC path.
	ErrIacScanPathUnsupported = "IaC scan path is not a supported Infrastructure as Code file or directory"

	// MsgNotAuthenticatedNoScan is the standard log line when a scanner skips work because there is no auth token.
	MsgNotAuthenticatedNoScan = "not authenticated, not scanning"
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
	ErrSnykCodeNotEnabledForFolder: {
		ShowNotification: false,
		TreeRootSuffix:   "(disabled in workspace)",
	},
	ErrSnykSecretsNotEnabled: {
		ShowNotification: false,
		TreeRootSuffix:   "(disabled at Snyk)",
	},
	ErrSnykSecretsNotEnabledForFolder: {
		ShowNotification: false,
		TreeRootSuffix:   "(disabled in workspace)",
	},
	ErrSnykIacNotEnabledForFolder: {
		ShowNotification: false,
		TreeRootSuffix:   "(disabled in workspace)",
	},
	ErrSnykOssNotEnabledForFolder: {
		ShowNotification: false,
		TreeRootSuffix:   "(disabled in workspace)",
	},
	ErrSastSettingsNotAvailable: {
		ShowNotification: false,
		TreeRootSuffix:   "(Code settings unavailable)",
	},
	ErrNoReferenceBranch: {
		ShowNotification: false,
		TreeRootSuffix:   "(no reference branch)",
	},
	ErrNoRepo: {
		ShowNotification: false,
		TreeRootSuffix:   "(repository not found)",
	},
	ErrOssScanPathUnsupported: {
		ShowNotification: false,
		TreeRootSuffix:   "(unsupported path)",
	},
	ErrIacScanPathUnsupported: {
		ShowNotification: false,
		TreeRootSuffix:   "(unsupported path)",
	},
	MsgNotAuthenticatedNoScan: {
		ShowNotification: false,
		TreeRootSuffix:   "(not authenticated)",
	},
}

var nonFailingScanErrors = map[string]bool{
	ErrOssScanPathUnsupported:         true,
	ErrIacScanPathUnsupported:         true,
	MsgNotAuthenticatedNoScan:         true,
	ErrSnykCodeNotEnabledForFolder:    true,
	ErrSnykIacNotEnabledForFolder:     true,
	ErrSnykOssNotEnabledForFolder:     true,
	ErrSnykSecretsNotEnabledForFolder: true,
	ErrSnykCodeNotEnabled:             true,
	ErrSnykSecretsNotEnabled:          true,
}

func IsNonFailingScanError(errorMessage string) bool {
	return nonFailingScanErrors[errorMessage]
}
