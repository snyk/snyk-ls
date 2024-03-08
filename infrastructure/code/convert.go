/*
 * © 2022-2024 Snyk Limited
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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/hexops/gotextdiff"
	"github.com/hexops/gotextdiff/myers"
	"github.com/hexops/gotextdiff/span"
	"github.com/rs/zerolog/log"
	codeClient "github.com/snyk/code-client-go"
	"golang.org/x/exp/slices"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/filesystem"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/util"
)

func createRuleLink() (u *url.URL) {
	u, err := url.Parse(codeDescriptionURL)
	if err != nil {
		return u
	}
	return u
}

func issueSeverityToMarkdown(severity snyk.Severity) string {
	switch severity {
	case snyk.Critical:
		return "🔥 Critical Severity"
	case snyk.High:
		return "🚨 High Severity"
	case snyk.Medium:
		return "⚠️ Medium Severity"
	case snyk.Low:
		return "⬇️ Low Severity"
	default:
		return "❔️ Unknown Severity"
	}
}

func (c *exampleCommit) toReference() (reference snyk.Reference) {
	commitURLString := c.fix.CommitURL
	commitURL, err := url.Parse(commitURLString)
	if err != nil {
		log.Err(err).
			Str("method", "code.toReference").
			Str("commitURL", commitURLString).
			Msgf("cannot parse commit url")
	}
	return snyk.Reference{Title: c.description, Url: commitURL}
}

func getIssueKey(ruleId string, path string, startLine int, endLine int, startCol int, endCol int) string {
	id := sha256.Sum256([]byte(ruleId + path + strconv.Itoa(startLine) + strconv.Itoa(endLine) + strconv.Itoa(startCol) + strconv.Itoa(endCol)))
	return hex.EncodeToString(id[:16])
}

type SarifConverter struct {
	sarif codeClient.SarifResponse
}

func (s *SarifConverter) getReferences(r codeClient.Rule) (references []snyk.Reference) {
	for _, commit := range s.getExampleCommits(r) {
		references = append(references, commit.toReference())
	}
	return references
}

func (s *SarifConverter) getCodeIssueType(r codeClient.Rule) snyk.Type {
	isSecurity := slices.ContainsFunc(r.Properties.Categories, func(category string) bool {
		return strings.ToLower(category) == "security"
	})

	if isSecurity {
		return snyk.CodeSecurityVulnerability
	}

	return snyk.CodeQualityIssue
}

func (s *SarifConverter) cwe(r codeClient.Rule) string {
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

func (s *SarifConverter) getCodeFlow(r codeClient.Result, baseDir string) (dataflow []snyk.DataFlowElement) {
	flows := r.CodeFlows
	dedupMap := map[string]bool{}
	for _, cFlow := range flows {
		threadFlows := cFlow.ThreadFlows
		for _, tFlow := range threadFlows {
			for _, tFlowLocation := range tFlow.Locations {
				method := "getCodeFlow"
				physicalLoc := tFlowLocation.Location.PhysicalLocation
				path := physicalLoc.ArtifactLocation.URI
				region := physicalLoc.Region
				myRange :=
					snyk.Range{
						Start: snyk.Position{
							Line:      region.StartLine - 1,
							Character: region.StartColumn - 1,
						},
						End: snyk.Position{
							Line:      region.EndLine - 1,
							Character: region.EndColumn,
						}}

				key := fmt.Sprintf("%sL%4d", path, region.StartLine)
				if !dedupMap[key] {
					fileUtil := filesystem.New()
					filePath := filepath.Join(baseDir, path)
					content, err := fileUtil.GetLineOfCode(filePath, myRange.Start.Line+1)
					if err != nil {
						log.Warn().Str("method", "code.getCodeFlow").Err(err).Msg("cannot load line Content from file")
					}
					d := snyk.DataFlowElement{
						Position:  len(dataflow),
						FilePath:  filePath,
						FlowRange: myRange,
						Content:   content,
					}
					log.Debug().Str("method", method).Str("DataFlowElement", d.String()).Send()
					dataflow = append(dataflow, d)
					dedupMap[key] = true
				}
			}
		}
	}
	return dataflow
}

func (s *SarifConverter) priorityScore(r codeClient.Result) string {
	priorityScore := r.Properties.PriorityScore
	if priorityScore == 0 {
		return ""
	}
	var builder strings.Builder
	builder.Grow(20)
	builder.WriteString(fmt.Sprintf(" | Priority Score %d", priorityScore))
	return builder.String()
}

func (s *SarifConverter) titleWithLeadingPipeOrEmpty(r codeClient.Rule) string {
	if r.ShortDescription.Text != "" {
		return fmt.Sprintf(" | %s", r.ShortDescription.Text)
	}
	return ""
}

func (s *SarifConverter) detailsOrEmpty(r codeClient.Rule) string {
	details := r.Help.Markdown
	if details != "" {
		return regexp.MustCompile(`##\sDetails`).ReplaceAllString(details, "### Details")
	}
	return ""
}

func (s *SarifConverter) formattedMessage(r codeClient.Result, rule codeClient.Rule, baseDir string) string {
	const separator = "\n\n\n\n"
	var builder strings.Builder
	builder.Grow(500)
	builder.WriteString(fmt.Sprintf("### %s", issueSeverityToMarkdown(issueSeverity(r.Level))))
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
	builder.WriteString(separator)
	builder.WriteString("### Data Flow\n\n")
	for _, elem := range s.getCodeFlow(r, baseDir) {
		builder.WriteString(elem.ToMarkDown())
	}
	builder.WriteString(separator)
	builder.WriteString("### Example Commit Fixes\n\n")
	for _, fix := range s.getExampleCommits(rule) {
		builder.WriteString(fix.toMarkdown())
	}
	builder.WriteString(separator)
	return builder.String()
}

func (s *SarifConverter) getMessage(r codeClient.Result, rule codeClient.Rule) string {
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

func (s *SarifConverter) getFixDescriptionsForRule(r codeClient.Rule, commitFixIndex int) string {
	fixDescriptions := r.Properties.ExampleCommitDescriptions
	if len(fixDescriptions) > commitFixIndex {
		return fixDescriptions[commitFixIndex]
	}
	return ""
}

func (s *SarifConverter) getExampleCommits(r codeClient.Rule) (exampleCommits []exampleCommit) {
	if len(r.Properties.ExampleCommitFixes) == 0 {
		return exampleCommits
	}
	for i, fix := range r.Properties.ExampleCommitFixes {
		exampleCommits = append(exampleCommits, exampleCommit{
			index:       i,
			description: s.getFixDescriptionsForRule(r, i),
			fix: codeClient.ExampleCommitFix{
				CommitURL: fix.CommitURL,
				Lines:     fix.Lines,
			},
		})
	}
	return exampleCommits
}

func (s *SarifConverter) getRule(r codeClient.Run, id string) codeClient.Rule {
	for _, r := range r.Tool.Driver.Rules {
		if r.ID == id {
			return r
		}
	}
	return codeClient.Rule{}
}

func (s *SarifConverter) toIssues(baseDir string) (issues []snyk.Issue, err error) {
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
			absPath, err := DecodePath(ToAbsolutePath(baseDir, loc.PhysicalLocation.ArtifactLocation.URI))
			if err != nil {
				log.Error().
					Err(err).
					Msg("failed to convert URI to absolute path: base directory: " +
						baseDir +
						", URI: " +
						loc.PhysicalLocation.ArtifactLocation.URI)
				errs = errors.Join(errs, err)
			}

			position := loc.PhysicalLocation.Region
			// NOTE: sarif uses 1-based location numbering, see
			// https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html#_Ref493492556
			startLine := position.StartLine - 1
			endLine := util.Max(position.EndLine-1, startLine)
			startCol := position.StartColumn - 1
			endCol := util.Max(position.EndColumn-1, 0)

			myRange := snyk.Range{
				Start: snyk.Position{
					Line:      startLine,
					Character: startCol,
				},
				End: snyk.Position{
					Line:      endLine,
					Character: endCol,
				},
			}

			testRule := s.getRule(r, result.RuleID)
			message := s.getMessage(result, testRule)
			formattedMessage := s.formattedMessage(result, testRule, baseDir)

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
			if issueType == snyk.CodeQualityIssue {
				isSecurityType = false
			}

			markers, err := s.getMarkers(result, baseDir)
			errs = errors.Join(errs, err)

			key := getIssueKey(result.RuleID, absPath, startLine, endLine, startCol, endCol)
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

			d := snyk.Issue{
				ID:                  result.RuleID,
				Range:               myRange,
				Severity:            issueSeverity(result.Level),
				Message:             message,
				FormattedMessage:    formattedMessage,
				IssueType:           issueType,
				AffectedFilePath:    absPath,
				Product:             product.ProductCode,
				IssueDescriptionURL: ruleLink,
				References:          s.getReferences(testRule),
				AdditionalData:      additionalData,
				CWEs:                testRule.Properties.Cwe,
			}

			issues = append(issues, d)
		}
	}
	return issues, errs
}

func (s *SarifConverter) getMarkers(r codeClient.Result, baseDir string) ([]snyk.Marker, error) {
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

			filePath, err := DecodePath(ToAbsolutePath(baseDir, loc.Location.PhysicalLocation.ArtifactLocation.URI))
			if err != nil {
				log.Error().
					Err(err).
					Msg("failed to convert URI to absolute path: base directory: " +
						baseDir +
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

// createAutofixWorkspaceEdit turns the returned fix into an edit.
func createAutofixWorkspaceEdit(absoluteFilePath string, fixedSourceCode string) (edit snyk.WorkspaceEdit) {
	singleTextEdit := snyk.TextEdit{
		Range: snyk.Range{
			// TODO(alex.gronskiy): should be changed to an actual hunk-like edit instead of
			// this "replace-the-whole-file" strategy
			Start: snyk.Position{
				Line:      0,
				Character: 0},
			End: snyk.Position{
				Line:      math.MaxInt32,
				Character: 0},
		},
		NewText: fixedSourceCode,
	}
	edit.Changes = make(map[string][]snyk.TextEdit)
	edit.Changes[absoluteFilePath] = []snyk.TextEdit{singleTextEdit}
	return edit
}

// toAutofixSuggestionsIssues converts the HTTP json-first payload to the domain type
func (s *AutofixResponse) toAutofixSuggestions(baseDir string, filePath string) (fixSuggestions []AutofixSuggestion) {
	for _, suggestion := range s.AutofixSuggestions {
		d := AutofixSuggestion{
			FixId:       suggestion.Id,
			AutofixEdit: createAutofixWorkspaceEdit(ToAbsolutePath(baseDir, filePath), suggestion.Value),
		}
		fixSuggestions = append(fixSuggestions, d)
	}

	return fixSuggestions
}

func (s *AutofixResponse) toUnifiedDiffSuggestions(baseDir string, filePath string) []AutofixUnifiedDiffSuggestion {
	logger := log.With().Str("method", "toUnifiedDiffSuggestions").Logger()
	var fixSuggestions []AutofixUnifiedDiffSuggestion
	for _, suggestion := range s.AutofixSuggestions {
		path := ToAbsolutePath(baseDir, filePath)
		fileContent, err := os.ReadFile(path)
		if err != nil {
			logger.Err(err).Msgf("cannot read fileContent %s", baseDir)
			return fixSuggestions
		}
		contentBefore := string(fileContent)
		edits := myers.ComputeEdits(span.URIFromPath(baseDir), contentBefore, suggestion.Value)
		unifiedDiff := fmt.Sprint(gotextdiff.ToUnified(baseDir, baseDir+"-fixed", contentBefore, edits))

		logger.Debug().Msgf(unifiedDiff)

		if len(edits) == 0 {
			return fixSuggestions
		}

		d := AutofixUnifiedDiffSuggestion{
			FixId:               suggestion.Id,
			UnifiedDiffsPerFile: map[string]string{},
		}
		d.UnifiedDiffsPerFile[path] = unifiedDiff
		fixSuggestions = append(fixSuggestions, d)
	}
	return fixSuggestions
}
