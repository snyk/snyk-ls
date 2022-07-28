package code

import (
	"fmt"
	"strings"
)

type exampleCommit struct {
	index       int
	description string
	fix         exampleCommitFix
}

func (c *exampleCommit) toMarkdown() (msg string) {
	fixDescription := c.description
	var builder strings.Builder
	builder.Grow(500)
	if fixDescription != "" {
		builder.WriteString(fmt.Sprintf("### [%s](%s)", fixDescription, c.fix.CommitURL))
	}
	builder.WriteString("\n\n```\n\n")
	for _, line := range c.fix.Lines {
		lineChangeChar := c.lineChangeChar(line.LineChange)
		builder.WriteString(fmt.Sprintf("%s %04d : %s\n", lineChangeChar, line.LineNumber, line.Line))
	}
	builder.WriteString("\n\n```\n\n")
	return builder.String()
}

func (c *exampleCommit) lineChangeChar(line string) string {
	switch line {
	case "none":
		return " "
	case "added":
		return "+"
	default:
		return "-"
	}
}
