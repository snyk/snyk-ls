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

package sdk

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog"
	"github.com/subosito/gotenv"

	"github.com/snyk/go-application-framework/pkg/envvars"

	"github.com/snyk/snyk-ls/internal/types"
)

func UpdateEnvironmentAndReturnAdditionalParams(sdks []types.LsSdk, logger zerolog.Logger) []string {
	logger = logger.With().Str("method", "UpdateEnvironmentAndReturnAdditionalParams").Logger()
	var additionalParameters []string
	for i := 0; i < len(sdks); i++ {
		sdk := sdks[i]
		path := sdk.Path
		pathExt := filepath.Join(path, "bin")
		env := gotenv.Env{}
		switch {
		case strings.Contains(strings.ToLower(sdk.Type), "java"):
			env["JAVA_HOME"] = path
		case strings.Contains(strings.ToLower(sdk.Type), "python"):
			symlinks, err := filepath.EvalSymlinks(path)
			if err != nil {
				symlinks = path
			}
			env["PYTHONPATH"] = symlinks
			env["PYTHONHOME"] = filepath.Dir(symlinks)
			pathExt = filepath.Dir(symlinks)
			additionalParameters = append(additionalParameters, "--command="+symlinks)
		case strings.Contains(strings.ToLower(sdk.Type), "go"):
			env["GOROOT"] = path
		}

		envvars.UpdatePath(pathExt, true)
		logger.Debug().Msg("prepended " + pathExt)
		for k, v := range env {
			_ = os.Setenv(k, v)
			logger.Debug().Any("env", env).Msg("added")
		}
	}
	return additionalParameters
}
