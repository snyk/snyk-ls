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

package storedconfig

import (
	"github.com/snyk/go-application-framework/pkg/configuration"
	"golang.org/x/exp/slices"

	"github.com/snyk/snyk-ls/internal/types"
)

// GetOrCreateFolderConfig queries git for the folder config of the given path
func GetOrCreateFolderConfig(conf configuration.Configuration, path string) (*types.FolderConfig, error) {
	folderConfig, err := folderConfigFromStorage(conf, path)
	if err != nil {
		return nil, err
	}

	gitFolderConfig, err := getFromGit(path)
	if err != nil {
		return folderConfig, nil
	}

	if folderConfig != nil && gitFolderConfig != nil {
		// the previous git configuration takes precedence
		folderConfig = mergeFolderConfigs(*gitFolderConfig, *folderConfig)
	}

	err = UpdateFolderConfig(conf, folderConfig)
	if err != nil {
		return nil, err
	}

	// remove git config
	// explicitly ignore any errors when removing it
	_ = DeleteSnykSubsection(path, path)
	return folderConfig, nil
}

// mergeFolderConfigs merges two folderConfigs, with the first taking precedence over the second
func mergeFolderConfigs(first types.FolderConfig, second types.FolderConfig) *types.FolderConfig {
	if second.FolderPath != first.FolderPath {
		return &first
	}

	// add all additional parameters that are not already in first
	if len(second.AdditionalParameters) > 0 {
		for _, parameter := range second.AdditionalParameters {
			if !slices.Contains(first.AdditionalParameters, parameter) {
				first.AdditionalParameters = append(first.AdditionalParameters, parameter)
			}
		}
	}

	if first.LocalBranches == nil && second.LocalBranches != nil {
		first.LocalBranches = second.LocalBranches
	}

	if first.BaseBranch == "" && second.BaseBranch != "" {
		first.BaseBranch = second.BaseBranch
	}

	return &first
}
