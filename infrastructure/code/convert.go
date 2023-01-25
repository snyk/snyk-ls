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

package code

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
)

func createRuleLink() (u *url.URL) {
	u, err := url.Parse(codeDescriptionURL)
	if err != nil {
		return u
	}
	return u
}

func getCommands(dataflow []dataflowElement) (commands []snyk.Command) {
	for _, element := range dataflow {
		commands = append(commands, element.toCommand())
	}
	return commands
}

func (r *rule) getReferences() (references []snyk.Reference) {
	for _, commit := range r.getExampleCommits() {
		references = append(references, commit.toReference())
	}
	return references
}

func (r *rule) getCodeIssueType() snyk.Type {
	const defaultType = snyk.CodeSecurityVulnerability

	if len(r.Categories) != 1 {
		return defaultType
	}

	switch strings.ToLower(r.Categories[0]) {
	case "defect":
		return snyk.CodeQualityIssue
	case "security":
		return snyk.CodeSecurityVulnerability
	default:
		return defaultType
	}
}

func (r *rule) cwe() string {
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

func (r *result) getCodeFlow() (dataflow []dataflowElement) {
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
						filePath:  path,
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

func (r *result) priorityScore() string {
	priorityScore := r.Properties.PriorityScore
	if priorityScore == 0 {
		return ""
	}
	var builder strings.Builder
	builder.Grow(20)
	builder.WriteString(fmt.Sprintf(" | Priority Score %d", priorityScore))
	return builder.String()
}

func (r *rule) titleWithLeadingPipeOrEmpty() string {
	if r.ShortDescription.Text != "" {
		return fmt.Sprintf(" | %s", r.ShortDescription.Text)
	}
	return ""
}

func (r *rule) detailsOrEmpty() string {
	details := r.Help.Markdown
	if details != "" {
		return regexp.MustCompile(`##\sDetails`).ReplaceAllString(details, "### Details")
	}
	return ""
}

func (r *result) formattedMessage(rule rule) string {
	const separator = "\n\n\n\n"
	var builder strings.Builder
	builder.Grow(500)
	builder.WriteString(fmt.Sprintf("### %s", issueSeverityToMarkdown(issueSeverity(r.Level))))
	builder.WriteString(rule.titleWithLeadingPipeOrEmpty())
	builder.WriteString(r.priorityScore())
	cwe := rule.cwe()
	if cwe != "" {
		builder.WriteString(" | ")
	}
	builder.WriteString(cwe)
	builder.WriteString(separator)
	builder.WriteString(r.Message.Text)
	builder.WriteString(separator)
	builder.WriteString(rule.detailsOrEmpty())
	builder.WriteString(separator)
	builder.WriteString("### Data Flow\n\n")
	for _, elem := range r.getCodeFlow() {
		builder.WriteString(elem.toMarkDown())
	}
	builder.WriteString(separator)
	builder.WriteString("### Example Commit Fixes\n\n")
	for _, fix := range rule.getExampleCommits() {
		builder.WriteString(fix.toMarkdown())
	}
	builder.WriteString(separator)
	return builder.String()
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

func (r *result) getMessage(rule rule) string {
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

func (r *rule) getFixDescriptionsForRule(commitFixIndex int) string {
	fixDescriptions := r.Properties.ExampleCommitDescriptions
	if len(fixDescriptions) > commitFixIndex {
		return fixDescriptions[commitFixIndex]
	}
	return ""
}

func (r *rule) getExampleCommits() (exampleCommits []exampleCommit) {
	if len(r.Properties.ExampleCommitFixes) == 0 {
		return exampleCommits
	}
	for i, fix := range r.Properties.ExampleCommitFixes {
		exampleCommits = append(exampleCommits, exampleCommit{
			index:       i,
			description: r.getFixDescriptionsForRule(i),
			fix: exampleCommitFix{
				CommitURL: fix.CommitURL,
				Lines:     fix.Lines,
			},
		})
	}
	return exampleCommits
}

func (r *run) getRule(id string) rule {
	for _, r := range r.Tool.Driver.Rules {
		if r.ID == id {
			return r
		}
	}
	return rule{}
}

func (s *SarifResponse) toIssues() (issues []snyk.Issue) {
	runs := s.Sarif.Runs
	if len(runs) == 0 {
		return issues
	}
	ruleLink := createRuleLink()

	r := runs[0]
	for _, result := range r.Results {
		for _, loc := range result.Locations {
			// convert the documentURI to a path according to our conversion
			path := loc.PhysicalLocation.ArtifactLocation.URI

			startLine := loc.PhysicalLocation.Region.StartLine - 1
			endLine := loc.PhysicalLocation.Region.EndLine - 1
			startCol := loc.PhysicalLocation.Region.StartColumn - 1
			endCol := loc.PhysicalLocation.Region.EndColumn

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

			rule := r.getRule(result.RuleID)
			message := result.getMessage(rule)
			dataflow := result.getCodeFlow()
			formattedMessage := result.formattedMessage(rule)

			exampleCommits := rule.getExampleCommits()
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

			issueType := rule.getCodeIssueType()
			isSecurityType := true
			if issueType == snyk.CodeQualityIssue {
				isSecurityType = false
			}

			additionalData := snyk.CodeIssueData{
				Rule:               rule.Name,
				RepoDatasetSize:    rule.Properties.RepoDatasetSize,
				ExampleCommitFixes: exampleFixes,
				CWE:                rule.Properties.Cwe,
				Text:               rule.Help.Markdown,
				Markers:            []snyk.Marker{}, // TODO: Clarify how to pull markers from the new API with Code Team
				Cols:               [2]int{startCol, endCol},
				Rows:               [2]int{startLine, endLine},
				IsSecurityType:     isSecurityType,
			}

			d := snyk.Issue{
				ID:                  result.RuleID,
				Range:               myRange,
				Severity:            issueSeverity(result.Level),
				Message:             message,
				FormattedMessage:    formattedMessage,
				IssueType:           issueType,
				AffectedFilePath:    path,
				Product:             product.ProductCode,
				IssueDescriptionURL: ruleLink,
				References:          rule.getReferences(),
				Commands:            getCommands(dataflow),
				AdditionalData:      additionalData,
			}

			if s.reportDiagnostic(d) {
				issues = append(issues, d)
			}
		}
	}
	return issues
}

func (s *SarifResponse) reportDiagnostic(d snyk.Issue) bool {
	c := config.CurrentConfig()
	return c.IsSnykCodeEnabled() ||
		c.IsSnykCodeSecurityEnabled() && d.IssueType == snyk.CodeSecurityVulnerability ||
		c.IsSnykCodeQualityEnabled() && d.IssueType == snyk.CodeQualityIssue
}
