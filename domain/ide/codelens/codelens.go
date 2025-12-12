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

// Package codelens implements the codelens functionality
package codelens

import (
	"fmt"

	"github.com/rs/zerolog"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/types"
)

type lensesWithIssueCount struct {
	lensCommands    []types.CommandData
	totalIssues     int
	unfixableIssues int
}

func GetFor(filePath types.FilePath) (lenses []sglsp.CodeLens) {
	c := config.CurrentConfig()
	logger := c.Logger().With().Str("method", "codelens.GetFor").Str("filePath", string(filePath)).Logger()
	f := c.Workspace().GetFolderContaining(filePath)
	if f == nil {
		return lenses
	}

	ip, ok := f.(snyk.IssueProvider)
	if !ok {
		return lenses
	}

	issues := ip.IssuesForFile(filePath)

	// group by range first - iterate over ALL issues to ensure CodeLens appear even when all are filtered
	lensesByRange := make(map[types.Range]*lensesWithIssueCount)
	for _, issue := range issues {
		if c.IsDeltaFindingsEnabled() && !issue.GetIsNew() {
			continue
		}
		for _, lens := range issue.GetCodelensCommands() {
			lensesWithIssueCountsForRange := lensesByRange[issue.GetRange()]
			if lensesWithIssueCountsForRange == nil {
				// For quickfix counts: use ALL issues in range
				allIssuesInRange := filterIssuesForRange(issues, issue.GetRange())

				// Count issues without any quickfix (actually unfixable)
				unfixableCount := countUnfixableIssues(allIssuesInRange)

				lensesWithIssueCountsForRange = &lensesWithIssueCount{
					lensCommands:    []types.CommandData{},
					totalIssues:     len(allIssuesInRange),
					unfixableIssues: unfixableCount,
				}
			}
			lensesWithIssueCountsForRange.lensCommands = append(lensesWithIssueCountsForRange.lensCommands, lens)
			lensesByRange[issue.GetRange()] = lensesWithIssueCountsForRange
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

// filterIssuesForRange filters issues to only those in the given range
func filterIssuesForRange(issues []types.Issue, r types.Range) []types.Issue {
	var issuesInRange []types.Issue
	for _, issue := range issues {
		if issue.GetRange().Overlaps(r) {
			issuesInRange = append(issuesInRange, issue)
		}
	}
	return issuesInRange
}

// countUnfixableIssues counts issues that don't have any quickfix available
func countUnfixableIssues(issues []types.Issue) int {
	count := 0
	for _, issue := range issues {
		hasQuickfix := false
		for _, action := range issue.GetCodeActions() {
			if action.GetGroupingType() == types.Quickfix {
				hasQuickfix = true
				break
			}
		}
		if !hasQuickfix {
			count++
		}
	}
	return count
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
			// Calculate fixable as total minus unfixable (matches code action logic)
			fixable := lensesWithIssueCount.totalIssues - lensesWithIssueCount.unfixableIssues
			if fixable > 1 {
				plural = "s"
			}
			unfixableSuffix := ""
			if lensesWithIssueCount.unfixableIssues > 0 {
				unfixableSuffix = fmt.Sprintf(" (%d unfixable)", lensesWithIssueCount.unfixableIssues)
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

func getCodeLensFromCommand(r types.Range, command types.CommandData) sglsp.CodeLens {
	return sglsp.CodeLens{
		Range: converter.ToRange(r),
		Command: sglsp.Command{
			Title:     command.Title,
			Command:   command.CommandId,
			Arguments: command.Arguments,
		},
	}
}
