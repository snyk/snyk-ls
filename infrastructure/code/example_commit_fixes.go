package code

import "fmt"

type exampleCommit struct {
	index       int
	description string
	fix         exampleCommitFix
}

func (c *exampleCommit) toMarkdown() (msg string) {
	fixDescription := c.description
	if fixDescription != "" {
		msg += fmt.Sprintf("### [%s](%s)", fixDescription, c.fix.CommitURL)
	}
	msg += "\n```\n"
	for _, line := range c.fix.Lines {
		lineChangeChar := c.lineChangeChar(line.LineChange)
		msg += fmt.Sprintf("%s %04d : %s\n", lineChangeChar, line.LineNumber, line.Line)
	}
	return msg + "```\n\n"
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
