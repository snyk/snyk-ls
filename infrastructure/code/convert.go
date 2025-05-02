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
	"github.com/rs/zerolog"
	"github.com/sourcegraph/go-diff/diff"
	"golang.org/x/exp/slices"

	codeClientSarif "github.com/snyk/code-client-go/sarif"
	sarif_utils "github.com/snyk/go-application-framework/pkg/utils/sarif"

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
				FindingId:           result.Fingerprints.SnykAssetFindingV1,
			}
			d.SetFingerPrint(result.Fingerprints.Num1)
			d.SetGlobalIdentity(result.Fingerprints.Identity)
			isIgnored, ignoreDetails := GetIgnoreDetailsFromSuppressions(result.Suppressions)
			d.IsIgnored = isIgnored
			d.IgnoreDetails = ignoreDetails
			d.AdditionalData = additionalData

			issues = append(issues, d)
		}
	}
	return issues, errs
}

func GetIgnoreDetailsFromSuppressions(suppressions []codeClientSarif.Suppression) (bool, *types.IgnoreDetails) {
	suppression, suppressionStatus := sarif_utils.GetHighestSuppression(suppressions)
	isIgnored := suppressionStatus == codeClientSarif.Accepted
	ignoreDetails := sarifSuppressionToIgnoreDetails(suppression)
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
		indicesRegex := regexp.MustCompile(`\((\d)\)`)
		// extract the location indices from the brackets (e.g. indices "1", "2" in the second array element from the above example)
		indices := indicesRegex.FindAllStringSubmatch(arg, -1)

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
		strRegex := regexp.MustCompile(`\[(.*?)]`)
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

func CreateWorkspaceEditFromDiff(zeroLogger *zerolog.Logger, absoluteFilePath string, diffContent string) (*types.WorkspaceEdit, error) {
	logger := zeroLogger.With().Str("method", "CreateWorkspaceEditFromDiff").Logger()
	logger.Debug().
		Str("absoluteFilePath", absoluteFilePath).
		Str("diffContent", diffContent).
		Msg("Attempting to create WorkspaceEdit for file from diff")

	// Validate input path
	if absoluteFilePath == "" {
		return nil, fmt.Errorf("no file recieved to apply diff to")
	}

	// Read the actual file content to validate diff line numbers
	fileContentBytes, err := os.ReadFile(absoluteFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s for validation: %w", absoluteFilePath, err)
	}
	logger.Debug().Int("fileBytes", len(fileContentBytes)).Msg("Read original file content")

	// Calculate the number of lines in the original file
	originalLines := strings.Split(string(fileContentBytes), "\n")
	originalLineCount := len(originalLines)
	logger.Debug().Int("originalLineCount", originalLineCount).Msg("Initial line count from split")
	// Adjust count if the file ends with a newline, which adds an empty string element
	// A file with "a\nb\n" has 2 lines, Split gives ["a", "b", ""], len 3.
	// A file with "a\nb" has 2 lines, Split gives ["a", "b"], len 2.
	// A file with "" (empty) has 0 lines, Split gives [""], len 1. -> Need special handling
	// A file with "\n" has 1 line, Split gives ["", ""], len 2.
	if len(fileContentBytes) == 0 {
		originalLineCount = 0 // Explicitly handle empty file
		logger.Debug().Msg("Detected empty file, setting originalLineCount to 0")
	} else if originalLineCount > 0 && originalLines[originalLineCount-1] == "" {
		// If the last element is empty, it's likely due to a trailing newline,
		// so the actual number of content lines is one less.
		originalLineCount--
		logger.Debug().Msg("Adjusted line count for trailing newline")
	}
	logger.Debug().Int("originalLineCount", originalLineCount).Msg("Calculated original file line count")

	if originalLineCount == 0 {
		return nil, fmt.Errorf("cannot apply a diff to an empty file")
	}

	// Parse the diff content assuming it's for a single file
	parsedDiff, err := diff.ParseFileDiff([]byte(diffContent))
	if err != nil {
		return nil, fmt.Errorf("failed to parse file diff: %w", err)
	}

	// If the diff is effectively empty (e.g., only headers or no changes), then error
	if parsedDiff == nil || len(parsedDiff.Hunks) == 0 {
		return nil, fmt.Errorf("empty diff")
	}

	var fileEdits []types.TextEdit
	for i, hunk := range parsedDiff.Hunks {
		hunkLogger := logger.With().Int("hunkIndex", i).Logger()
		hunkLogger.Debug().
			Int32("origStartLine", hunk.OrigStartLine).
			Int32("origLines", hunk.OrigLines).
			Int32("newStartLine", hunk.NewStartLine).
			Int32("newLines", hunk.NewLines).
			Msg("Processing hunk")

		hunkEdits, err := processHunk(&hunkLogger, hunk, originalLines)
		if err != nil {
			return nil, fmt.Errorf("error processing hunk %d: %w", i, err)
		}
		hunkLogger.Debug().Int("editsFromHunk", len(hunkEdits)).Msg("Successfully processed hunk")
		fileEdits = append(fileEdits, hunkEdits...)
	}

	logger.Debug().Int("totalEdits", len(fileEdits)).Msg("Aggregated edits from all hunks")
	if len(fileEdits) == 0 {
		return nil, fmt.Errorf("diff contained no edits")
	}

	// Build the WorkspaceEdit
	workspaceEdit := &types.WorkspaceEdit{
		Changes: make(map[string][]types.TextEdit),
	}
	workspaceEdit.Changes[absoluteFilePath] = fileEdits

	// Log the final structure
	logger.Debug().Interface("finalWorkspaceEdit", workspaceEdit).Msg("Returning final WorkspaceEdit")

	return workspaceEdit, nil
}

// processHunk converts a single diff hunk into a slice of LSP TextEdits.
func processHunk(logger *zerolog.Logger, hunk *diff.Hunk, originalLines []string) ([]types.TextEdit, error) {
	originalLineCount := int32(len(originalLines))
	// originalLineCount stores the total number of lines in the original file
	// (equivalent to 1-based line number of the last line + 1, or 0 if empty).
	// Diff lines are 1-based.

	logger.Debug().Int32("originalLineCount", originalLineCount).Msg("processHunk started")
	// Check if hunk range is valid relative to the original file size.
	if hunk.OrigLines > 0 { // Modifies/deletes lines
		logger.Debug().Msg("Validating hunk range (modify/delete)")
		// Hunk modifies/deletes lines. Check start and end.
		// Start line must be within the file bounds.
		if hunk.OrigStartLine == 0 || hunk.OrigStartLine > originalLineCount {
			// If file is empty (count=0), any start line > 0 is invalid for non-insertion.
			if originalLineCount == 0 && hunk.OrigStartLine > 0 {
				return nil, fmt.Errorf("hunk applies changes starting at line %d, but file is empty", hunk.OrigStartLine)
			}
			return nil, fmt.Errorf("hunk starts at line %d but file only has %d lines", hunk.OrigStartLine, originalLineCount)
		}
		// End line check - must be within the file bounds.
		hunkEndLine := hunk.OrigStartLine + hunk.OrigLines - 1
		if hunkEndLine > originalLineCount {
			return nil, fmt.Errorf("hunk applies changes up to line %d but file only has %d lines", hunkEndLine, originalLineCount)
		}
	} else {
		logger.Debug().Msg("Validating hunk range (pure insertion)")
		// Pure insertion (hunk.OrigLines == 0).
		// Insertion happens *before* OrigStartLine.
		// Valid insertion points are line 1 to line originalLineCount + 1.
		if hunk.OrigStartLine == 0 || hunk.OrigStartLine > originalLineCount+1 {
			return nil, fmt.Errorf("hunk insertion point %d is outside valid range [1, %d] for file with %d lines", hunk.OrigStartLine, originalLineCount+1, originalLineCount)
		}
	}
	logger.Debug().Msg("Hunk range validation passed")

	var edits []types.TextEdit
	// Split hunk body into lines. Remove a single trailing newline before splitting to avoid an extra empty element.
	hunkBodyStr := string(hunk.Body)
	// Log raw hunk body before processing
	logger.Debug().Str("hunkBodyRaw", hunkBodyStr).Msg("Raw Hunk Body")
	lines := strings.Split(strings.TrimSuffix(hunkBodyStr, "\n"), "\n")
	logger.Debug().Int("hunkBodyLines", len(lines)).Msg("Split hunk body into lines")

	// Diff lines are 1-based, LSP is 0-based. Track current original line.
	currentOrigLine := hunk.OrigStartLine - 1 // Convert to 0-based index
	if currentOrigLine < 0 {
		// This should be impossible if initial hunk validation (OrigStartLine >= 1) is correct.
		return nil, fmt.Errorf("internal error: calculated currentOrigLine %d from OrigStartLine %d is invalid after initial validation", currentOrigLine, hunk.OrigStartLine)
	}
	logger.Debug().Int32("initialCurrentOrigLine", currentOrigLine).Msg("Initialized current original line (0-based)")

	var deletions []string // Lines beginning '-'
	var additions []string // Lines beginning '+'
	// Track the original line number where the current deletion/insertion block started (0-based)
	startChangeLine := int32(-1)

	// Helper to create and append TextEdit based on collected changes
	flushChanges := func() error {
		flushLogger := logger.With().Str("helper", "flushChanges").Logger()
		if len(deletions) == 0 && len(additions) == 0 {
			flushLogger.Debug().Msg("No pending changes to flush.")
			return nil // Nothing to flush
		}
		flushLogger.Debug().
			Int("deletionsCount", len(deletions)).
			Int("additionsCount", len(additions)).
			Int32("startChangeLineBefore", startChangeLine).
			Int32("currentOrigLine", currentOrigLine). // Log context line number
			Msg("Flushing changes")

		if startChangeLine == -1 {
			// If startChangeLine wasn't set (pure add/del at hunk start),
			// use the initial currentOrigLine for the hunk (which is 0-based start line - 1)
			startChangeLine = hunk.OrigStartLine - 1
			if startChangeLine < 0 {
				// This should be impossible if initial hunk validation is correct,
				// as OrigStartLine should always be >= 1.
				flushLogger.Error().Int32("invalidOrigStartLine", hunk.OrigStartLine).Msg("Calculated startChangeLine is negative, indicates invalid hunk OrigStartLine")
				return fmt.Errorf("internal error: calculated startChangeLine %d based on OrigStartLine %d is invalid", startChangeLine, hunk.OrigStartLine)
			}
			flushLogger.Debug().Int32("startChangeLine", startChangeLine).Msg("startChangeLine was -1, now set to hunk start line")
		} else {
			flushLogger.Debug().Int32("startChangeLine", startChangeLine).Msg("Using previously set startChangeLine")
		}

		startPos := types.Position{Line: int(startChangeLine), Character: 0}
		// End line is the start line + number of lines being deleted (0-based)
		// For insertion (0 deletions), end line is same as start line.
		endPos := types.Position{Line: int(startChangeLine) + len(deletions), Character: 0}
		editRange := types.Range{Start: startPos, End: endPos}

		newText := ""
		if len(additions) > 0 {
			// Ensure trailing newline consistent with diff format that expects lines
			newText = strings.Join(additions, "\n") + "\n"
			flushLogger.Debug().Str("newText", newText).Msg("Generated new text for addition")
		} else {
			flushLogger.Debug().Msg("No additions, new text is empty (deletion)")
		}

		// If only additions (insertion), make range zero-length at the start position
		if len(deletions) == 0 {
			flushLogger.Debug().Msg("End set to start")
			editRange.End = editRange.Start
			// Ensure insertion point is correct
			// If additions started right at the hunk start, startChangeLine is already correct.
			// If additions started after some context, startChangeLine was set correctly.
		}

		generatedEdit := types.TextEdit{Range: editRange, NewText: newText}
		flushLogger.Debug().
			Interface("range", generatedEdit.Range).
			Str("newText", generatedEdit.NewText).
			Int("newTextLen", len(generatedEdit.NewText)).
			Msg("Generated TextEdit")

		edits = append(edits, generatedEdit)

		// Reset collectors
		deletions = nil
		additions = nil
		startChangeLine = -1 // Reset for the next block
		flushLogger.Debug().Msg("Reset deletion/addition collectors and startChangeLine")
		return nil
	}

	for i, line := range lines {
		lineLogger := logger.With().Int("lineIndex", i).Str("rawLine", line).Logger()

		// Handle potential empty line if Split produced one unnecessarily
		// Or lines that might just be whitespace (though unlikely in valid diff body)
		if len(line) == 0 {
			// If the original body ended with \n, Split might give an empty string at the end.
			// Context lines already advance the line counter. Add/Delete implicitly handle lines.
			// We can generally ignore genuinely empty lines within the hunk body processing loop.
			lineLogger.Debug().Msg("Skipping empty line in hunk body")
			continue
		}
		// Handle "\ No newline at end of file" marker - treat as informational, doesn't affect edits.
		if line == "\\ No newline at end of file" || strings.HasPrefix(line, "\\ ") { // Allow for potential space
			lineLogger.Debug().Msg("Skipping '\\ No newline...' marker")
			continue
		}

		op := line[0]
		// Check if line has content beyond the operator
		content := ""
		if len(line) > 1 {
			content = line[1:]
		}
		lineLogger = lineLogger.With().Str("op", string(op)).Str("content", content).Logger()

		switch op {
		case ' ': // Context line
			lineLogger.Debug().Int32("currentOrigLineBefore", currentOrigLine).Msg("Processing context line")

			// --- Logging some extra validation ---
			// Check bounds before accessing originalLines
			if int(currentOrigLine) >= 0 && int(currentOrigLine) < len(originalLines) {
				originalContent := originalLines[currentOrigLine]
				diffContextContent := content // Content from the diff line (line[1:])
				match := originalContent == diffContextContent
				lineLogger.Debug().
					Int32("expectedOrigLineIndex", currentOrigLine).
					Str("diffContextContent", diffContextContent).
					Str("actualOriginalContent", originalContent).
					Bool("contentMatches", match).
					Msg("Validating context line against original file content")
				if !match {
					return nil, fmt.Errorf("content line mismatch detected! Cannot apply diff otherwise unexpected content may be deleted")
				}
			} else {
				// This would indicate a more fundamental issue if hit after initial hunk validation
				lineLogger.Error().
					Int32("currentOrigLine", currentOrigLine).
					Int("originalLinesLength", len(originalLines)).
					Msg("currentOrigLine out of bounds for originalLines during context validation!")
				return nil, fmt.Errorf("currentOrigLine out of bounds for originalLines during context validation")
			}
			// --- --- ---

			// Before processing context, flush any pending changes.
			if len(deletions) > 0 || len(additions) > 0 {
				lineLogger.Debug().Msg("Context line encountered, flushing pending changes first")
			} else {
				lineLogger.Debug().Msg("Context line encountered, no pending changes to flush")
			}
			err := flushChanges()
			if err != nil {
				return nil, err
			}

			// Sanity check: Does this context line exist in the original?
			// currentOrigLine is 0-based index. originalLineCount is 1-based count.
			if currentOrigLine >= originalLineCount {
				// This indicates an inconsistent diff - context line refers beyond file end.
				// The initial hunk check should ideally prevent this.
				return nil, fmt.Errorf("internal error: context line refers to line %d but file only has %d lines", currentOrigLine+1, originalLineCount)
			}
			currentOrigLine++    // Advance line count for context (stays 0-based)
			startChangeLine = -1 // Reset start marker as context breaks change block
			lineLogger.Debug().Int32("currentOrigLineAfter", currentOrigLine).Msg("Advanced currentOrigLine for context")

		case '-': // Deletion line
			lineLogger.Debug().Int32("currentOrigLine", currentOrigLine).Msg("Processing deletion line")
			// If transitioning from adding to deleting, flush adds first
			if len(additions) > 0 { // Change from adding to deleting implies finishing the add block
				lineLogger.Debug().Msg("Transition from add to delete, flushing additions first")
				err := flushChanges()
				if err != nil {
					return nil, err
				}
			}
			// If this is the first change in a block, mark where it starts
			if startChangeLine == -1 {
				startChangeLine = currentOrigLine // Mark start of change block (0-based & deletion)
				lineLogger.Debug().Int32("startChangeLine", startChangeLine).Msg("Set startChangeLine for new deletion block")
			}
			// Sanity check: Does this deleted line exist?
			// The deletion refers to 'currentOrigLine' before it's conceptually removed.
			if currentOrigLine >= originalLineCount {
				return nil, fmt.Errorf("internal error: attempting to delete line %d but file only has %d lines", currentOrigLine+1, originalLineCount)
			}
			deletions = append(deletions, content)
			lineLogger.Debug().Int("deletionsCount", len(deletions)).Msg("Appended to deletions")
			// Deletion consumes an original line, so advancing currentOrigLine.
			currentOrigLine++
		case '+': // Addition line
			lineLogger.Debug().Int32("currentOrigLine", currentOrigLine).Msg("Processing addition line")
			// If this is the first change in a block (or first after deletions), mark insert point.
			if startChangeLine == -1 {
				startChangeLine = currentOrigLine // Mark start of change block (insertion/replacement point) (0-based)
				lineLogger.Debug().Int32("startChangeLine", startChangeLine).Msg("Set startChangeLine for new addition/replacement block")
			}
			additions = append(additions, content)
			lineLogger.Debug().Int("additionsCount", len(additions)).Msg("Appended to additions")
			// Addition does not consume an original line.

		default:
			return nil, fmt.Errorf("invalid line prefix %q in hunk body: %q", op, line)
		}
	}

	logger.Debug().Msg("Finished processing lines in hunk body, performing final flush")
	err := flushChanges() // Flush any remaining changes at the end of the hunk
	if err != nil {
		return nil, err
	}

	logger.Debug().Int("totalEditsInHunk", len(edits)).Msg("processHunk finished")
	return edits, nil
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
