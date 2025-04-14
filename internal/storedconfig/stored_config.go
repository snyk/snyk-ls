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
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/internal/types"
)

// GetOrCreateFolderConfig queries git for the folder config of the given path
func GetOrCreateFolderConfig(conf configuration.Configuration, path types.FilePath, logger *zerolog.Logger) (*types.FolderConfig, error) {
	folderConfig, err := folderConfigFromStorage(conf, path, nil)
	if err != nil {
		return nil, err
	}

	err = UpdateFolderConfig(conf, folderConfig, logger)
	if err != nil {
		return nil, err
	}

	return folderConfig, nil
}
