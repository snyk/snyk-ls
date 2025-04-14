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
	"strings"

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

// SliceContainsParam checks if the parameter name is equal by splitting the given
// arguments in the args array for the '=' parameter and comparing it to the same
// split done with parameter. Returns true, if the left-hand side of the parameter
// is already contained in args.
func SliceContainsParam(args []string, parameter string) bool {
	for _, arg := range args {
		leftOfArg := strings.Split(arg, "=")[0]
		leftOfParameter := strings.Split(parameter, "=")[0]
		if leftOfParameter == leftOfArg {
			return true
		}
	}
	return false
}
