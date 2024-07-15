/*
 * © 2022 Snyk Limited All rights reserved.
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

package codelens

import (
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/types"
)

func GetFor(filePath string) (lenses []sglsp.CodeLens) {
	f := workspace.Get().GetFolderContaining(filePath)
	if f == nil {
		return lenses
	}

	issues := f.IssuesForFile(filePath)

	// group by range first
	lensesByRange := make(map[snyk.Range][]types.Groupable)
	for _, issue := range issues {
		for _, lens := range issue.CodelensCommands {
			commands := lensesByRange[issue.Range]
			if commands == nil {
				commands = []types.Groupable{}
			}
			commands = append(commands, lens)
			lensesByRange[issue.Range] = commands
		}
	}

	for r, commands := range lensesByRange {
		quickFixLensCommand := getQuickFixLensCommand(commands)
		if quickFixLensCommand != nil {
			lenses = append(lenses, getCodeLensFromCommand(r, *quickFixLensCommand))
		}
	}

	return lenses
}

func getQuickFixLensCommand(groupables []types.Groupable) *types.CommandData {
	// right now we can always group by max semver version, as
	// code only has one quickfix available, and iac none at all
	var quickFix *types.CommandData
	qf, ok := types.MaxSemver()(groupables).(types.CommandData)
	if !ok {
		quickFix = nil
	} else {
		quickFix = &qf
	}
	return quickFix
}

func getCodeLensFromCommand(r snyk.Range, command types.CommandData) sglsp.CodeLens {
	return sglsp.CodeLens{
		Range: converter.ToRange(r),
		Command: sglsp.Command{
			Title:     command.Title,
			Command:   command.CommandId,
			Arguments: command.Arguments,
		},
	}
}
