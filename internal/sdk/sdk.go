/*
 * © 2024 Snyk Limited
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

// Package sdk implements SDK environment handling
package sdk

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/subosito/gotenv"

	env "github.com/snyk/snyk-ls/internal"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
)

const pathEnvVarName = "PATH"

// UpdateEnvironmentAndReturnAdditionalParams returns additional parameters and updated env for the given SDK
func UpdateEnvironmentAndReturnAdditionalParams(c *config.Config, sdks []types.LsSdk) ([]string, gotenv.Env) {
	logger := c.Logger().With().Str("method", "UpdateEnvironmentAndReturnAdditionalParams").Logger()
	var additionalParameters []string

	// env update
	env := env.GetEnvFromSystemAndConfiguration(c.Engine().GetConfiguration(), c.GetUserSettingsPath(), &logger)

	// update process environment with sdk info
	for i := 0; i < len(sdks); i++ {
		sdk := sdks[i]
		path := sdk.Path
		pathExt := filepath.Join(path, "bin")
		switch {
		case strings.Contains(strings.ToLower(sdk.Type), "java"):
			env["JAVA_HOME"] = path
		case strings.Contains(strings.ToLower(sdk.Type), "python"):
			pathExt = filepath.Dir(path)
			additionalParameters = append(additionalParameters, "--command="+path)
		case strings.Contains(strings.ToLower(sdk.Type), "go"):
			env["GOROOT"] = path
		}

		env[pathEnvVarName] = getPath(pathExt, true)
		logger.Debug().Msg("prepended " + pathExt)
	}
	return additionalParameters, env
}

// UpdatePath prepends or appends the extension to the current path.
// For append, if the entry is already there, it will not be re-added / moved.
// For prepend, if the entry is already there, it will be correctly re-prioritized to the front.
//
//	pathExtension string the path component to be added.
//	prepend bool whether to pre- or append
func getPath(pathExtension string, prepend bool) string {
	currentPath := os.Getenv(pathEnvVarName)

	if pathExtension == "" {
		return currentPath
	}

	if currentPath == "" {
		return pathExtension
	}

	currentPathEntries := strings.Split(currentPath, string(os.PathListSeparator))
	addPathEntries := strings.Split(pathExtension, string(os.PathListSeparator))

	var combinedSliceWithDuplicates []string
	if prepend {
		combinedSliceWithDuplicates = append(addPathEntries, currentPathEntries...)
	} else {
		combinedSliceWithDuplicates = append(currentPathEntries, addPathEntries...)
	}

	newPathSlice := utils.Dedupe(combinedSliceWithDuplicates)

	newPath := strings.Join(newPathSlice, string(os.PathListSeparator))
	return newPath
}
