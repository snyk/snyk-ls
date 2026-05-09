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

package env

import (
	"os"
	"path/filepath"

	"github.com/snyk/go-application-framework/pkg/envvars"
	"github.com/subosito/gotenv"
)

// DisableShellEnvLoadingEnvVar is checked by every snyk-ls call site before
// invoking envvars.LoadConfiguredEnvironment. Set it to any value other than
// "", "0", or "false" (e.g. "1") in test harnesses to prevent GAF from
// spawning `bash --login -i`, which performs job-control initialisation via
// tcsetpgrp and can seize the controlling terminal from the test process,
// causing SIGTTIN/SIGTTOU to suspend `make test`.
//
// Production binaries leave this variable unset; behavior is identical to
// before this guard was introduced.
const DisableShellEnvLoadingEnvVar = "SNYK_LS_DISABLE_SHELL_ENV_LOADING"

// LoadShellEnvUnlessDisabled wraps envvars.LoadConfiguredEnvironment so that
// test harnesses can opt out of the bash --login -i subprocess invocation.
//
// When DisableShellEnvLoadingEnvVar is set to any value other than "", "0",
// or "false", the bash shell invocation is skipped but custom config files
// are still loaded (matching the non-shell side-effects of the underlying GAF
// call). Returns true when the shell call was skipped, false when it ran.
//
// Production binaries leave the env var unset; behavior is identical to
// before this guard was introduced.
func LoadShellEnvUnlessDisabled(customConfigFiles []string, workingDirectory string) (skipped bool) {
	switch os.Getenv(DisableShellEnvLoadingEnvVar) {
	case "", "0", "false":
		envvars.LoadConfiguredEnvironment(customConfigFiles, workingDirectory)
		return false
	default:
		// Skip the bash --login -i invocation, but still apply any custom
		// config files so that features depending on them (e.g. the CLI
		// extension executor) continue to work under tests.
		loadConfigFilesOnly(customConfigFiles, workingDirectory)
		return true
	}
}

// loadConfigFilesOnly replicates the config-file side of GAF's
// LoadConfiguredEnvironment (the `loadFile` loop) without invoking the shell.
func loadConfigFilesOnly(customConfigFiles []string, workingDirectory string) {
	for _, file := range customConfigFiles {
		if file == "" {
			continue
		}
		if !filepath.IsAbs(file) && workingDirectory != "" {
			file = filepath.Join(workingDirectory, file)
		}
		path := os.Getenv("PATH")
		if err := gotenv.OverLoad(file); err != nil {
			continue
		}
		envvars.UpdatePath(path, false)
	}
}
