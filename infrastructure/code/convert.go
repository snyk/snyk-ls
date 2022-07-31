package code

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/domain/snyk"
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

func (r *result) getFormattedMessage(rule rule) string {
	const separator = "\n\n\n\n"
	var builder strings.Builder
	builder.Grow(500)
	builder.WriteString(fmt.Sprintf("### %s", issueSeverityToMarkdown(issueSeverity(r.Level))))
	builder.WriteString(r.priorityScore())
	cwe := rule.cwe()
	if cwe != "" {
		builder.WriteString(" | ")
	}
	builder.WriteString(cwe)
	builder.WriteString("\n\n\n\n")
	builder.WriteString(r.Message.Text)
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
	case snyk.High:
		return "🚨 High Severity"
	case snyk.Medium:
		return "⚠️ Medium Severity"
	case snyk.Low:
		return "⬇️ Low Severity"
	default:
		return "⬇️ Low Severity"
	}
}

func (r *result) getMessage() string {
	text := r.Message.Text
	if len(text) > 100 {
		text = text[:100] + "..."
	}
	return fmt.Sprintf("%s (Snyk)", text)
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

			myRange := snyk.Range{
				Start: snyk.Position{
					Line:      loc.PhysicalLocation.Region.StartLine - 1,
					Character: loc.PhysicalLocation.Region.StartColumn - 1,
				},
				End: snyk.Position{
					Line:      loc.PhysicalLocation.Region.EndLine - 1,
					Character: loc.PhysicalLocation.Region.EndColumn,
				},
			}

			rule := r.getRule(result.RuleID)
			message := result.getMessage()
			dataflow := result.getCodeFlow()
			formattedMessage := result.getFormattedMessage(rule)

			d := snyk.Issue{
				ID:                  result.RuleID,
				Range:               myRange,
				Severity:            issueSeverity(result.Level),
				Message:             message,
				FormattedMessage:    formattedMessage,
				IssueType:           snyk.CodeSecurityVulnerability,
				AffectedFilePath:    path,
				Product:             snyk.ProductCode,
				IssueDescriptionURL: ruleLink,
				References:          rule.getReferences(),
				Commands:            getCommands(dataflow),
			}

			issues = append(issues, d)
		}
	}
	return issues
}
