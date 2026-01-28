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

package command

import (
	"context"
	"path/filepath"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/diagnostics/directory_check"
	"github.com/snyk/snyk-ls/internal/types"
)

type directoryDiagnosticsCommand struct {
	command types.CommandData
	c       *config.Config
}

func (cmd *directoryDiagnosticsCommand) Command() types.CommandData {
	return cmd.command
}

func (cmd *directoryDiagnosticsCommand) Execute(_ context.Context) (any, error) {
	logger := cmd.c.Logger().With().Str("command", "directoryDiagnostics").Str("method", "Execute").Logger()

	// Parse additional directories from arguments if provided
	var additionalDirs []directory_check.UsedDirectory
	if len(cmd.command.Arguments) > 0 {
		if dirsArg, ok := cmd.command.Arguments[0].([]any); ok {
			additionalDirs = parseAdditionalDirs(dirsArg)
		}
	}

	// Add configured CLI path directory if set
	cliPath := cmd.c.CliSettings().Path()
	if cliPath != "" {
		cliDir := filepath.Dir(cliPath)
		additionalDirs = append(additionalDirs, directory_check.UsedDirectory{
			PathWanted:    cliDir,
			Purpose:       "Configured CLI Path",
			MayContainCLI: true,
		})
		logger.Debug().Str("cliPath", cliPath).Str("cliDir", cliDir).Msg("Added configured CLI path to diagnostics")
	}

	logger.Debug().Int("additionalDirs", len(additionalDirs)).Msg("Running directory diagnostics")

	// Run diagnostics
	result := directory_check.RunDiagnostics(&logger, additionalDirs)

	// Format as plain text (no color)
	output := directory_check.FormatResultsText(result, false)

	return output, nil
}

// parseAdditionalDirs converts the JSON arguments to UsedDirectory structs
func parseAdditionalDirs(dirsArg []any) []directory_check.UsedDirectory {
	var dirs []directory_check.UsedDirectory
	for _, d := range dirsArg {
		if dirMap, ok := d.(map[string]any); ok {
			dir := directory_check.UsedDirectory{}
			if pathWanted, ok := dirMap["pathWanted"].(string); ok {
				dir.PathWanted = pathWanted
			}
			if purpose, ok := dirMap["purpose"].(string); ok {
				dir.Purpose = purpose
			}
			if mayContainCLI, ok := dirMap["mayContainCLI"].(bool); ok {
				dir.MayContainCLI = mayContainCLI
			}
			if dir.PathWanted != "" {
				dirs = append(dirs, dir)
			}
		}
	}
	return dirs
}
