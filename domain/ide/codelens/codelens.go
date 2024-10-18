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
	"fmt"

	"github.com/rs/zerolog"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/types"
)

type lensesWithIssueCount struct {
	lensCommands []types.CommandData
	issueCount   int
	totalIssues  int
}

func GetFor(filePath string) (lenses []sglsp.CodeLens) {
	c := config.CurrentConfig()
	logger := c.Logger().With().Str("method", "codelens.GetFor").Str("filePath", filePath).Logger()
	f := workspace.Get().GetFolderContaining(filePath)
	if f == nil {
		return lenses
	}

	issues := f.IssuesForFile(filePath)

	// group by range first
	lensesByRange := make(map[snyk.Range]*lensesWithIssueCount)
	for _, issue := range issues {
		if c.IsDeltaFindingsEnabled() && !issue.IsNew {
			continue
		}
		for _, lens := range issue.CodelensCommands {
			lensesWithIssueCountsForRange := lensesByRange[issue.Range]
			if lensesWithIssueCountsForRange == nil {
				lensesWithIssueCountsForRange = &lensesWithIssueCount{
					lensCommands: []types.CommandData{},
					issueCount:   0,
					totalIssues:  len(f.IssuesForRange(filePath, issue.Range)),
				}
			}
			lensesWithIssueCountsForRange.lensCommands = append(lensesWithIssueCountsForRange.lensCommands, lens)
			lensesWithIssueCountsForRange.issueCount++
			lensesByRange[issue.Range] = lensesWithIssueCountsForRange
		}
	}

	for r, commands := range lensesByRange {
		lensCommands := getLensCommands(commands, logger)
		for _, command := range lensCommands {
			lens := getCodeLensFromCommand(r, command)
			lenses = append(lenses, lens)
		}
	}

	return lenses
}

func getLensCommands(lensesWithIssueCount *lensesWithIssueCount, logger zerolog.Logger) []types.CommandData {
	groupableByType := map[types.GroupingType][]types.Groupable{}
	for _, groupable := range lensesWithIssueCount.lensCommands {
		commands := groupableByType[groupable.GetGroupingType()]
		if commands == nil {
			commands = []types.Groupable{}
		}

		groupableByType[groupable.GetGroupingType()] = append(commands, groupable)
	}

	lenses := []types.CommandData{}
	for groupingType, lensCommands := range groupableByType {
		if groupingType == types.Quickfix {
			// right now we can always group by max semver version, as
			// code only has one quickfix available, and iac none at all
			qf, ok := types.MaxSemver(logger)(lensCommands).(types.CommandData)
			plural := ""
			fixable := lensesWithIssueCount.issueCount
			unfixable := lensesWithIssueCount.totalIssues - fixable
			if fixable > 1 {
				plural = "s"
			}
			unfixableSuffix := ""
			if unfixable > 1 {
				unfixableSuffix = fmt.Sprintf(" (%d unfixable)", unfixable)
			}
			qf.Title = fmt.Sprintf("%s and fix %d issue%s%s", qf.Title, fixable, plural, unfixableSuffix)
			if ok {
				lenses = append(lenses, qf)
			}
		} else {
			// add all other lenses
			for _, lensCommand := range lensCommands {
				lens, ok := lensCommand.(types.CommandData)
				if ok {
					lenses = append(lenses, lens)
				}
			}
		}
	}

	return lenses
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
