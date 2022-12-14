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
	builder.WriteString("\n```\n")
	for _, line := range c.fix.Lines {
		lineChangeChar := c.lineChangeChar(line.LineChange)
		builder.WriteString(fmt.Sprintf("%s %04d : %s\n", lineChangeChar, line.LineNumber, line.Line))
	}
	builder.WriteString("\n```\n")
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
