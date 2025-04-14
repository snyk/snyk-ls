/*
 * © 2022-2025 Snyk Limited
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

package code

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hexops/gotextdiff"
	"github.com/hexops/gotextdiff/myers"
	"github.com/hexops/gotextdiff/span"
	"golang.org/x/exp/slices"

	codeClientSarif "github.com/snyk/code-client-go/sarif"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/filesystem"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

func createRuleLink() (u *url.URL) {
	u, err := url.Parse(codeDescriptionURL)
	if err != nil {
		return u
	}
	return u
}

func issueSeverityToMarkdown(severity types.Severity) string {
	switch severity {
	case types.Critical:
		return "🔥 Critical Severity"
	case types.High:
		return "🚨 High Severity"
	case types.Medium:
		return "⚠️ Medium Severity"
	case types.Low:
		return "⬇️ Low Severity"
	default:
		return "❔️ Unknown Severity"
	}
}

func (c *exampleCommit) toReference() (reference types.Reference) {
	conf := config.CurrentConfig()
	commitURLString := c.fix.CommitURL
	commitURL, err := url.Parse(commitURLString)
	if err != nil {
		conf.Logger().Err(err).
			Str("method", "code.toReference").
			Str("commitURL", commitURLString).
			Msgf("cannot parse commit url")
	}
	return types.Reference{Title: c.description, Url: commitURL}
}

type SarifConverter struct {
	sarif codeClientSarif.SarifResponse
	c     *config.Config
}

func (s *SarifConverter) getReferences(r codeClientSarif.Rule) (references []types.Reference) {
	for _, commit := range s.getExampleCommits(r) {
		references = append(references, commit.toReference())
	}
	return references
}

func (s *SarifConverter) getCodeIssueType(r codeClientSarif.Rule) types.IssueType {
	isSecurity := slices.ContainsFunc(r.Properties.Categories, func(category string) bool {
		return strings.ToLower(category) == "security"
	})

	if isSecurity {
		return types.CodeSecurityVulnerability
	}

	return types.CodeQualityIssue
}

func (s *SarifConverter) cwe(r codeClientSarif.Rule) string {
	count := len(r.Properties.Cwe)
	if count == 0 {
		return ""
	}
	builder := strings.Builder{}
	builder.Grow(100)
	ending := "y"
	if count > 1 {
		ending = "ies"
	}
	builder.WriteString(fmt.Sprintf("Vulnerabilit%s: ", ending))
	for i, cwe := range r.Properties.Cwe {
		if i > 0 {
			builder.WriteString(" | ")
		}
		builder.WriteString(fmt.Sprintf(
			"[%s](%s)",
			cwe,
			fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", strings.Split(cwe, "-")[1])))
	}
	builder.WriteString("\n\n\n")
	return builder.String()
}

func (s *SarifConverter) getCodeFlow(r codeClientSarif.Result, baseDir types.FilePath) (dataflow []snyk.DataFlowElement) {
	flows := r.CodeFlows
	dedupMap := map[string]bool{}
	for _, cFlow := range flows {
		threadFlows := cFlow.ThreadFlows
		for _, tFlow := range threadFlows {
			for _, tFlowLocation := range tFlow.Locations {
				method := "getCodeFlow"
				physicalLoc := tFlowLocation.Location.PhysicalLocation
				path, err := DecodePath(ToAbsolutePath(baseDir, types.FilePath(physicalLoc.ArtifactLocation.URI)))
				if err != nil {
					s.c.Logger().Error().
						Err(err).
						Msg("failed to convert URI to absolute path: base directory: " +
							string(baseDir) +
							", URI: " +
							physicalLoc.ArtifactLocation.URI)
					continue
				}
				region := physicalLoc.Region
				myRange :=
					types.Range{
						Start: types.Position{
							Line:      region.StartLine - 1,
							Character: region.StartColumn - 1,
						},
						End: types.Position{
							Line:      region.EndLine - 1,
							Character: region.EndColumn,
						}}

				key := fmt.Sprintf("%sL%4d", path, region.StartLine)
				if !dedupMap[key] {
					fileUtil := filesystem.New()
					content, err := fileUtil.GetLineOfCode(path, myRange.Start.Line+1)
					if err != nil {
						s.c.Logger().Warn().Str("method", "code.getCodeFlow").Err(err).Msg("cannot load line Content from file")
					}
					d := snyk.DataFlowElement{
						Position:  len(dataflow),
						FilePath:  types.FilePath(path),
						FlowRange: myRange,
						Content:   content,
					}
					s.c.Logger().Debug().Str("method", method).Str("DataFlowElement", d.String()).Send()
					dataflow = append(dataflow, d)
					dedupMap[key] = true
				}
			}
		}
	}
	return dataflow
}

func (s *SarifConverter) priorityScore(r codeClientSarif.Result) string {
	priorityScore := r.Properties.PriorityScore
	if priorityScore == 0 {
		return ""
	}
	var builder strings.Builder
	builder.Grow(20)
	builder.WriteString(fmt.Sprintf(" | Priority Score %d", priorityScore))
	return builder.String()
}

func (s *SarifConverter) titleWithLeadingPipeOrEmpty(r codeClientSarif.Rule) string {
	if r.ShortDescription.Text != "" {
		return fmt.Sprintf(" | %s", r.ShortDescription.Text)
	}
	return ""
}

func (s *SarifConverter) detailsOrEmpty(r codeClientSarif.Rule) string {
	details := r.Help.Markdown
	if details != "" {
		return regexp.MustCompile(`##\s`).ReplaceAllString(details, "### ")
	}
	return ""
}

func (s *SarifConverter) formattedMessageMarkdown(r codeClientSarif.Result, rule codeClientSarif.Rule, baseDir types.FilePath) string {
	hoverVerbosity := s.c.HoverVerbosity()
	var builder strings.Builder
	const separator = "\n\n\n\n"
	if hoverVerbosity >= 1 {
		builder.Grow(500)
		builder.WriteString(fmt.Sprintf("## %s", issueSeverityToMarkdown(issueSeverity(r.Level))))
		builder.WriteString(s.titleWithLeadingPipeOrEmpty(rule))
		builder.WriteString(s.priorityScore(r))
		cwe := s.cwe(rule)
		if cwe != "" {
			builder.WriteString(" | ")
		}
		builder.WriteString(cwe)
		builder.WriteString(separator)
		builder.WriteString(r.Message.Text)
		builder.WriteString(separator)
		builder.WriteString(s.detailsOrEmpty(rule))
	}

	if hoverVerbosity >= 2 {
		builder.WriteString(separator)
		builder.WriteString("### Data Flow\n\n")
		for _, elem := range s.getCodeFlow(r, baseDir) {
			builder.WriteString(elem.ToMarkDown())
		}
	}

	if hoverVerbosity == 3 {
		builder.WriteString(separator)
		builder.WriteString("### Example Commit Fixes\n\n")
		for _, fix := range s.getExampleCommits(rule) {
			builder.WriteString(fix.toMarkdown())
		}
		builder.WriteString(separator)

		references := s.getReferences(rule)
		if len(references) > 0 {
			builder.WriteString("\n\nReferences:\n\n")
			for _, reference := range references {
				builder.WriteString(fmt.Sprintf("[%s](%s)\n\n", reference.Title, reference.Url))
			}
		}
	}
	return builder.String()
}

func (s *SarifConverter) getMessage(r codeClientSarif.Result, rule codeClientSarif.Rule) string {
	text := r.Message.Text
	if rule.ShortDescription.Text != "" {
		text = fmt.Sprintf("%s: %s", rule.ShortDescription.Text, text)
	}
	const maxLength = 100
	if len(text) > maxLength {
		text = text[:maxLength] + "..."
	}
	return text
}

func (s *SarifConverter) getFixDescriptionForRule(r codeClientSarif.Rule, commitFixIndex int) string {
	fixDescriptions := r.Properties.ExampleCommitDescriptions
	if len(fixDescriptions) > commitFixIndex {
		return fixDescriptions[commitFixIndex]
	}
	return ""
}

func (s *SarifConverter) getExampleCommits(r codeClientSarif.Rule) (exampleCommits []exampleCommit) {
	if len(r.Properties.ExampleCommitFixes) == 0 {
		return exampleCommits
	}
	for i, fix := range r.Properties.ExampleCommitFixes {
		fixDescription := s.getFixDescriptionForRule(r, i)
		if fixDescription == "" {
			before, _, _ := strings.Cut(fix.CommitURL, "/commit")
			fixDescription = before
		}
		exampleCommits = append(exampleCommits, exampleCommit{
			index:       i,
			description: fixDescription,
			fix: codeClientSarif.ExampleCommitFix{
				CommitURL: fix.CommitURL,
				Lines:     fix.Lines,
			},
		})
	}
	return exampleCommits
}

func (s *SarifConverter) getRule(r codeClientSarif.Run, id string) codeClientSarif.Rule {
	for _, r := range r.Tool.Driver.Rules {
		if r.ID == id {
			return r
		}
	}
	return codeClientSarif.Rule{}
}

func (s *SarifConverter) toIssues(baseDir types.FilePath) (issues []types.Issue, err error) {
	runs := s.sarif.Sarif.Runs
	if len(runs) == 0 {
		return issues, nil
	}
	ruleLink := createRuleLink()

	r := runs[0]
	var errs error
	for _, result := range r.Results {
		for _, loc := range result.Locations {
			// Response contains encoded relative paths that should be decoded and converted to absolute.
			absPath, err := DecodePath(ToAbsolutePath(baseDir, types.FilePath(loc.PhysicalLocation.ArtifactLocation.URI)))
			if err != nil {
				s.c.Logger().Error().
					Err(err).
					Msg("failed to convert URI to absolute path: base directory: " +
						string(baseDir) +
						", URI: " +
						loc.PhysicalLocation.ArtifactLocation.URI)
				errs = errors.Join(errs, err)
				continue
			}

			position := loc.PhysicalLocation.Region
			// NOTE: sarif uses 1-based location numbering, see
			// https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html#_Ref493492556
			startLine := position.StartLine - 1
			endLine := util.Max(position.EndLine-1, startLine)
			startCol := position.StartColumn - 1
			endCol := util.Max(position.EndColumn-1, 0)
			myRange := types.Range{
				Start: types.Position{
					Line:      startLine,
					Character: startCol,
				},
				End: types.Position{
					Line:      endLine,
					Character: endCol,
				},
			}

			testRule := s.getRule(r, result.RuleID)
			message := s.getMessage(result, testRule)
			formattedMessage := s.formattedMessageMarkdown(result, testRule, baseDir)

			exampleCommits := s.getExampleCommits(testRule)
			exampleFixes := make([]snyk.ExampleCommitFix, 0, len(exampleCommits))
			for _, commit := range exampleCommits {
				commitURL := commit.fix.CommitURL
				commitFixLines := make([]snyk.CommitChangeLine, 0, len(commit.fix.Lines))
				for _, line := range commit.fix.Lines {
					commitFixLines = append(commitFixLines, snyk.CommitChangeLine{
						Line:       line.Line,
						LineNumber: line.LineNumber,
						LineChange: line.LineChange})
				}

				exampleFixes = append(exampleFixes, snyk.ExampleCommitFix{
					CommitURL: commitURL,
					Lines:     commitFixLines,
				})
			}

			issueType := s.getCodeIssueType(testRule)
			isSecurityType := true
			if issueType == types.CodeQualityIssue {
				isSecurityType = false
			}

			markers, err := s.getMarkers(result, baseDir)
			errs = errors.Join(errs, err)

			key := util.GetIssueKey(result.RuleID, absPath, startLine, endLine, startCol, endCol)
			title := testRule.ShortDescription.Text
			if title == "" {
				title = testRule.ID
			}

			additionalData := snyk.CodeIssueData{
				Key:                key,
				Title:              title,
				Message:            result.Message.Text,
				Rule:               testRule.Name,
				RuleId:             testRule.ID,
				RepoDatasetSize:    testRule.Properties.RepoDatasetSize,
				ExampleCommitFixes: exampleFixes,
				CWE:                testRule.Properties.Cwe,
				Text:               testRule.Help.Markdown,
				Markers:            markers,
				Cols:               [2]int{startCol, endCol},
				Rows:               [2]int{startLine, endLine},
				IsSecurityType:     isSecurityType,
				IsAutofixable:      result.Properties.IsAutofixable,
				PriorityScore:      result.Properties.PriorityScore,
				DataFlow:           s.getCodeFlow(result, baseDir),
			}

			d := &snyk.Issue{
				ID:                  result.RuleID,
				Range:               myRange,
				Severity:            issueSeverity(result.Level),
				Message:             message,
				FormattedMessage:    formattedMessage,
				IssueType:           issueType,
				ContentRoot:         baseDir,
				AffectedFilePath:    types.FilePath(absPath),
				Product:             product.ProductCode,
				IssueDescriptionURL: ruleLink,
				References:          s.getReferences(testRule),
				AdditionalData:      additionalData,
				CWEs:                testRule.Properties.Cwe,
				FindingsId:          result.Fingerprints.SnykAssetFindingV1,
			}
			d.SetFingerPrint(result.Fingerprints.Num1)
			d.SetGlobalIdentity(result.Fingerprints.Identity)
			isIgnored, ignoreDetails := GetIgnoreDetailsFromSuppressions(s.c, result.Suppressions)
			d.IsIgnored = isIgnored
			d.IgnoreDetails = ignoreDetails
			d.AdditionalData = additionalData

			issues = append(issues, d)
		}
	}
	return issues, errs
}

func GetIgnoreDetailsFromSuppressions(c *config.Config, suppressions []codeClientSarif.Suppression) (bool, *types.IgnoreDetails) {
	logger := c.Logger().With().Str("method", "GetIgnoreDetailsFromSuppressions").Logger()
	isIgnored := false
	var ignoreDetails *types.IgnoreDetails
	// this can be an array of multiple suppressions in SARIF,
	// but we only store one ignore for now
	if len(suppressions) > 0 {
		if len(suppressions) > 1 {
			logger.Warn().Int("number of SARIF suppressions", len(suppressions)).Msg(
				"there are more suppressions than expected")
		}
		isIgnored = true
		ignoreDetails = sarifSuppressionToIgnoreDetails(&suppressions[0])
	}
	return isIgnored, ignoreDetails
}

func sarifSuppressionToIgnoreDetails(suppression *codeClientSarif.Suppression) *types.IgnoreDetails {
	if suppression == nil {
		return nil
	}

	reason := suppression.Justification
	if reason == "" {
		reason = "None given"
	}
	ignoreDetails := &types.IgnoreDetails{
		Category:   string(suppression.Properties.Category),
		Reason:     reason,
		Expiration: parseExpirationDateFromString(suppression.Properties.Expiration),
		IgnoredOn:  parseDateFromString(suppression.Properties.IgnoredOn),
		IgnoredBy:  suppression.Properties.IgnoredBy.Name,
		Status:     suppression.Status,
	}
	return ignoreDetails
}

func parseExpirationDateFromString(date *string) string {
	if date == nil {
		return ""
	}

	parsedDate := parseDateFromString(*date)
	return parsedDate.Format(time.RFC3339)
}

func parseDateFromString(date string) time.Time {
	logger := config.CurrentConfig().Logger().With().Str("method", "convert.parseDateFromString").Logger()
	layouts := []string{
		"Mon Jan 02 2006", // TODO: when this gets fixed, we can remove this option [IGNR-365]
		time.RFC3339,      // Standard format
	}

	for _, layout := range layouts {
		if t, err := time.Parse(layout, date); err == nil {
			return t
		}
	}

	// Fallback to today's date if parsing fails
	logger.Warn().Str("date", date).Msg("failed to parse date. Using current date.")
	return time.Now().UTC()
}

func (s *SarifConverter) getMarkers(r codeClientSarif.Result, baseDir types.FilePath) ([]snyk.Marker, error) {
	markers := make([]snyk.Marker, 0)

	// Example markdown string:
	// "Printing the stack trace of {0}. Production code should not use {1}. {3}"
	markdownStr := r.Message.Markdown

	// Example message arguments array:
	// "arguments": [
	// 	"[java.lang.InterruptedException](0)",
	// 	"[printStackTrace](1)(2)",
	// 	"[This is a test argument](3)"
	// ]
	for i, arg := range r.Message.Arguments {
		indecesRegex := regexp.MustCompile(`\((\d)\)`)
		// extract the location indices from the brackets (e.g. indices "1", "2" in the second array element from the above example)
		indices := indecesRegex.FindAllStringSubmatch(arg, -1)

		positions := make([]snyk.MarkerPosition, 0)
		for _, match := range indices {
			index, _ := strconv.Atoi(match[1])

			if len(r.CodeFlows) == 0 || len(r.CodeFlows[0].ThreadFlows) == 0 || len(r.CodeFlows[0].ThreadFlows[0].Locations) <= index {
				continue
			}

			// Every CodeFlow location maps to the index within the message argument
			loc := r.CodeFlows[0].ThreadFlows[0].Locations[index]

			startLine := loc.Location.PhysicalLocation.Region.StartLine - 1
			endLine := loc.Location.PhysicalLocation.Region.EndLine - 1
			startCol := loc.Location.PhysicalLocation.Region.StartColumn - 1
			endCol := loc.Location.PhysicalLocation.Region.EndColumn

			filePath, err := DecodePath(ToAbsolutePath(baseDir, types.FilePath(loc.Location.PhysicalLocation.ArtifactLocation.URI)))
			if err != nil {
				s.c.Logger().Error().
					Err(err).
					Msg("failed to convert URI to absolute path: base directory: " +
						string(baseDir) +
						", URI: " +
						loc.Location.PhysicalLocation.ArtifactLocation.URI)
				return []snyk.Marker{}, err
			}
			positions = append(positions, snyk.MarkerPosition{
				Rows: [2]int{startLine, endLine},
				Cols: [2]int{startCol, endCol},
				File: filePath,
			})
		}

		// extract the text between the brackets
		strRegex := regexp.MustCompile(`\[(.*?)\]`)
		// extract the text between the brackets (e.g. "printStackTrace" in the second array element from the above example)
		if strFindResult := strRegex.FindStringSubmatch(arg); len(strFindResult) > 1 {
			substituteStr := strFindResult[1]

			// compute index to insert markers
			indexTemplate := fmt.Sprintf("{%d}", i)
			msgStartIndex := strings.LastIndex(markdownStr, indexTemplate)
			msgEndIndex := msgStartIndex + len(substituteStr) - 1

			markdownStr = strings.Replace(markdownStr, indexTemplate, substituteStr, 1)

			// write the marker
			markers = append(markers, snyk.Marker{
				Msg: [2]int{msgStartIndex, msgEndIndex},
				Pos: positions,
			})
		}
	}

	return markers, nil
}

// CreateWorkspaceEditFromDiff turns the returned fix (in diff format) into a series of TextEdits in a WorkspaceEdit.
func CreateWorkspaceEditFromDiff(absoluteFilePath string, diff string) (edit types.WorkspaceEdit) {
	fileContentBytes, err := os.ReadFile(absoluteFilePath)
	if err != nil || len(fileContentBytes) == 0 {
		return edit
	}
	fileContentLineStrings := strings.Split(string(fileContentBytes), "\n")

	var textEdits []types.TextEdit

	var hunkLine = 0   // Location in the current hunk
	var hunkOffset = 0 // Whether we need to offset the current hunk based on previous edits.

	// Loop over the diff. Diffs will always use \n instead of \r\n, so no need to sanitize (see getUnifiedDiff).
	for _, line := range strings.Split(diff, "\n") {
		// If we are being asked to make changes outside the original file, abort and return an empty edit.
		if hunkLine-hunkOffset > len(fileContentLineStrings) {
			return edit
		}

		if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+++") {
			continue // We ignore header lines
		} else if strings.HasPrefix(line, "@@") {
			r := regexp.MustCompile(`@@ -(\d+),?(\d*) \+(\d+),?(\d*) @@`)
			matches := r.FindStringSubmatch(line)
			if matches == nil {
				return edit // We have a badly formatted diff, so abort.
			}

			hunkLine, _ = strconv.Atoi(matches[1]) // Apply the edit from the first line of the original file in the diff
			hunkLine -= 1                          // TextEdit range is 0-indexed, whereas LSP diff is 1-indexed
			hunkLine += hunkOffset                 // Account for any previous additions or deletions.
		} else if strings.HasPrefix(line, "-") {
			textEdit := buildOneLineTextEdit(hunkLine, hunkLine+1, "")
			textEdits = append(textEdits, textEdit)
			hunkOffset -= 1 // We've removed a line, so future hunks will be offset with respect to the diff.
		} else if strings.HasPrefix(line, "+") {
			textEdit := buildOneLineTextEdit(hunkLine, hunkLine, strings.TrimPrefix(line, "+")+"\n")
			textEdits = append(textEdits, textEdit)
			hunkOffset += 1 // We've added a line, so future hunks will be offset with respect to the diff.
			hunkLine += 1   // We've added a line, so increment the pointer in our current hunk.
		} else if strings.HasPrefix(line, " ") {
			hunkLine += 1 // We skip over unchanged lines, so increment the pointer in our current hunk.
		}
	}

	edit.Changes = make(map[string][]types.TextEdit)
	edit.Changes[absoluteFilePath] = textEdits

	return edit
}

func buildOneLineTextEdit(startLine int, endLine int, text string) types.TextEdit {
	if startLine > endLine {
		return types.TextEdit{} // We should never reach this. Return an empty edit if the input it invalid.
	}

	return types.TextEdit{
		Range: types.Range{
			Start: types.Position{
				Line:      startLine,
				Character: 0,
			},
			End: types.Position{
				Line:      endLine,
				Character: 0,
			},
		},
		NewText: text,
	}
}

func (s *AutofixResponse) toUnifiedDiffSuggestions(baseDir types.FilePath, filePath types.FilePath) []AutofixUnifiedDiffSuggestion {
	var fixSuggestions []AutofixUnifiedDiffSuggestion
	for _, suggestion := range s.AutofixSuggestions {
		decodedPath, unifiedDiff := getPathAndUnifiedDiff(baseDir, filePath, suggestion.Value)
		if decodedPath == "" || unifiedDiff == "" {
			continue
		}

		d := AutofixUnifiedDiffSuggestion{
			FixId:               suggestion.Id,
			UnifiedDiffsPerFile: map[string]string{},
		}

		d.UnifiedDiffsPerFile[string(decodedPath)] = string(unifiedDiff)
		fixSuggestions = append(fixSuggestions, d)
	}
	return fixSuggestions
}

func getPathAndUnifiedDiff(baseDir types.FilePath, filePath types.FilePath, newText string) (decodedPath types.FilePath, unifiedDiff types.FilePath) {
	logger := config.CurrentConfig().Logger().With().Str("method", "getUnifiedDiff").Logger()

	decodedPathString, err := DecodePath(ToAbsolutePath(baseDir, filePath))
	decodedPath = types.FilePath(decodedPathString)
	if err != nil {
		logger.Err(err).Msgf("cannot decode filePath %s", filePath)
		return
	}
	logger.Debug().Msgf("File decodedPath %s", decodedPath)

	fileContent, err := os.ReadFile(decodedPathString)
	if err != nil {
		logger.Err(err).Msgf("cannot read fileContent %s", decodedPath)
		return
	}

	// Workaround: AI Suggestion API only returns \n new lines. It doesn't consider carriage returns.
	contentBefore := strings.Replace(string(fileContent), "\r\n", "\n", -1)
	edits := myers.ComputeEdits(span.URIFromPath(decodedPathString), contentBefore, newText)
	unifiedDiff = types.FilePath(fmt.Sprint(gotextdiff.ToUnified(decodedPathString, decodedPathString+"fixed", contentBefore, edits)))

	return decodedPath, unifiedDiff
}
