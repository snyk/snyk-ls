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

// GetStoredFolderConfigOptions controls the behavior of folder config retrieval
type GetStoredFolderConfigOptions struct {
	// CreateIfNotExist creates a new folder config if one doesn't exist.
	// When ReadOnly=false: creates and saves to storage.
	// When ReadOnly=true: creates in-memory but doesn't save.
	CreateIfNotExist bool
	// ReadOnly prevents any writes to storage.
	// Configs are returned but not saved.
	ReadOnly bool
	// EnrichFromGit enriches the folder config with Git branch information.
	EnrichFromGit bool
}

// GetStoredFolderConfigWithOptions retrieves folder config from storage with specified behaviors
func GetStoredFolderConfigWithOptions(conf configuration.Configuration, path types.FilePath, logger *zerolog.Logger, opts GetStoredFolderConfigOptions) (*types.FolderConfig, error) {
	l := logger.With().Str("method", "GetStoredFolderConfigWithOptions").Logger()

	folderConfig, err := folderConfigFromStorage(conf, path, &l, opts.CreateIfNotExist)
	if err != nil {
		return nil, err
	}

	// If folder config doesn't exist and we're not creating, return nil
	if folderConfig == nil && !opts.CreateIfNotExist {
		return nil, nil
	}

	// Enrich from git if requested
	if opts.EnrichFromGit {
		folderConfig = enrichFromGit(&l, folderConfig)
	}

	// Update storage since we may have changed values like normalizing the path, enriching from git, etc., but skip if read-only mode.
	if !opts.ReadOnly {
		err = UpdateStoredFolderConfig(conf, folderConfig, &l)
		if err != nil {
			return nil, err
		}
	}

	return folderConfig, nil
}

// GetOrCreateStoredFolderConfig gets folder config from storage and merges it with Git data.
// Creates the config if it doesn't exist and writes back to storage.
func GetOrCreateStoredFolderConfig(conf configuration.Configuration, path types.FilePath, logger *zerolog.Logger) (*types.FolderConfig, error) {
	return GetStoredFolderConfigWithOptions(conf, path, logger, GetStoredFolderConfigOptions{
		CreateIfNotExist: true,
		ReadOnly:         false,
		EnrichFromGit:    true,
	})
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
