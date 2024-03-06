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

package code

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	codeClient "github.com/snyk/code-client-go"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/util"
)

func toIssues(s *codeClient.SarifResponse, baseDir string) (issues []snyk.Issue, err error) {
	runs := s.Sarif.Runs
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

			rule := getRule(r, result.RuleID)
			message := getMessage(result, rule)
			formattedMessage := formattedMessage(result, rule, baseDir)

			exampleCommits := getExampleCommits(rule)
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

			issueType := getCodeIssueType(rule)
			isSecurityType := true
			if issueType == snyk.CodeQualityIssue {
				isSecurityType = false
			}

			markers, err := getMarkers(result, baseDir)
			errs = errors.Join(errs, err)

			key := getIssueKey(result.RuleID, absPath, startLine, endLine, startCol, endCol)
			title := rule.ShortDescription.Text
			if title == "" {
				title = rule.ID
			}

			additionalData := snyk.CodeIssueData{
				Key:                key,
				Title:              title,
				Message:            result.Message.Text,
				Rule:               rule.Name,
				RuleId:             rule.ID,
				RepoDatasetSize:    rule.Properties.RepoDatasetSize,
				ExampleCommitFixes: exampleFixes,
				CWE:                rule.Properties.Cwe,
				Text:               rule.Help.Markdown,
				Markers:            markers,
				Cols:               [2]int{startCol, endCol},
				Rows:               [2]int{startLine, endLine},
				IsSecurityType:     isSecurityType,
				IsAutofixable:      result.Properties.IsAutofixable,
				PriorityScore:      result.Properties.PriorityScore,
			}

			d := snyk.Issue{
				ID:        result.RuleID,
				Range:     myRange,
				Severity:  issueSeverity(result.Level),
				Message:   message,
				IsIgnored: false, // TODO: check feature flag
				IgnoreDetails: &snyk.IgnoreDetails{
					Reason: "",
					Expiry: time.Time{},
				},
				FormattedMessage:    formattedMessage,
				IssueType:           issueType,
				AffectedFilePath:    absPath,
				Product:             product.ProductCode,
				IssueDescriptionURL: ruleLink,
				References:          getReferences(rule),
				AdditionalData:      additionalData,
				CWEs:                rule.Properties.Cwe,
			}

			issues = append(issues, d)
		}
	}
	return issues, errs
}

func getCodeIssueType(r codeClient.Rule) snyk.Type {
	isSecurity := slices.ContainsFunc(r.Properties.Categories, func(category string) bool {
		return strings.ToLower(category) == "security"
	})

	if isSecurity {
		return snyk.CodeSecurityVulnerability
	}

	return snyk.CodeQualityIssue
}

func getRule(r codeClient.Run, id string) codeClient.Rule {
	for _, r := range r.Tool.Driver.Rules {
		if r.ID == id {
			return r
		}
	}
	return codeClient.Rule{}
}

func formattedMessage(r codeClient.Result, rule codeClient.Rule, baseDir string) string {
	const separator = "\n\n\n\n"
	var builder strings.Builder
	builder.Grow(500)
	builder.WriteString(fmt.Sprintf("### %s", issueSeverityToMarkdown(issueSeverity(r.Level))))
	builder.WriteString(titleWithLeadingPipeOrEmpty(rule))
	builder.WriteString(priorityScore(r))
	cwe := cwe(rule)
	if cwe != "" {
		builder.WriteString(" | ")
	}
	builder.WriteString(cwe)
	builder.WriteString(separator)
	builder.WriteString(r.Message.Text)
	builder.WriteString(separator)
	builder.WriteString(detailsOrEmpty(rule))
	builder.WriteString(separator)
	builder.WriteString("### Data Flow\n\n")
	for _, elem := range getCodeFlow(r, baseDir) {
		builder.WriteString(elem.toMarkDown())
	}
	builder.WriteString(separator)
	builder.WriteString("### Example Commit Fixes\n\n")
	for _, fix := range getExampleCommits(rule) {
		builder.WriteString(fix.toMarkdown())
	}
	builder.WriteString(separator)
	return builder.String()
}

func getMessage(r codeClient.Result, rule codeClient.Rule) string {
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

func getReferences(r codeClient.Rule) (references []snyk.Reference) {
	for _, commit := range getExampleCommits(r) {
		references = append(references, commit.toReference())
	}
	return references
}

func getExampleCommits(r codeClient.Rule) (exampleCommits []exampleCommit) {
	if len(r.Properties.ExampleCommitFixes) == 0 {
		return exampleCommits
	}
	for i, fix := range r.Properties.ExampleCommitFixes {
		exampleCommits = append(exampleCommits, exampleCommit{
			index:       i,
			description: getFixDescriptionsForRule(r, i),
			fix: exampleCommitFix{
				CommitURL: fix.CommitURL,
				Lines:     fix.Lines,
			},
		})
	}
	return exampleCommits
}

func getFixDescriptionsForRule(r codeClient.Rule, commitFixIndex int) string {
	fixDescriptions := r.Properties.ExampleCommitDescriptions
	if len(fixDescriptions) > commitFixIndex {
		return fixDescriptions[commitFixIndex]
	}
	return ""
}

func getMarkers(r codeClient.Result, baseDir string) ([]snyk.Marker, error) {
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

func priorityScore(r codeClient.Result) string {
	priorityScore := r.Properties.PriorityScore
	if priorityScore == 0 {
		return ""
	}
	var builder strings.Builder
	builder.Grow(20)
	builder.WriteString(fmt.Sprintf(" | Priority Score %d", priorityScore))
	return builder.String()
}

func titleWithLeadingPipeOrEmpty(r codeClient.Rule) string {
	if r.ShortDescription.Text != "" {
		return fmt.Sprintf(" | %s", r.ShortDescription.Text)
	}
	return ""
}

func detailsOrEmpty(r codeClient.Rule) string {
	details := r.Help.Markdown
	if details != "" {
		return regexp.MustCompile(`##\sDetails`).ReplaceAllString(details, "### Details")
	}
	return ""
}

func cwe(r codeClient.Rule) string {
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

func getCodeFlow(r codeClient.Result, baseDir string) (dataflow []dataflowElement) {
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
					d := dataflowElement{
						position:  len(dataflow),
						filePath:  filepath.Join(baseDir, path),
						flowRange: myRange,
					}
					log.Debug().Str("method", method).Str("dataflowElement", d.String()).Send()
					dataflow = append(dataflow, d)
					dedupMap[key] = true
				}
			}
		}
	}
	return dataflow
}
