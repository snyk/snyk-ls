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

package snyk

import (
	"math"
	"strings"
)

type TextEdit struct {
	/**
	 * The range of the text document to be manipulated. To insert
	 * text into a document create a range where start === end.
	 */
	Range Range

	/**
	 * The string to be inserted. For delete operations use an
	 * empty string.
	 */
	NewText string
}

func (e *TextEdit) SanitizeRange() {
	// check text length and number of lines and adjust range in text edit
	// to not go out of bounds
	if e.NewText == "" {
		e.Range = Range{}
		return
	}

	posixLineSeparator := "\n"
	windowsLineSeparator := "\r\n"
	normalizedText := strings.Replace(e.NewText, windowsLineSeparator, posixLineSeparator, -1)
	lines := strings.Split(normalizedText, posixLineSeparator)

	if e.Range.Start.Line > len(lines) {
		// we can't recover here, reset the edit
		e.NewText = ""
		e.Range = Range{}
		return
	}

	if e.Range.Start.Character > len(lines[e.Range.Start.Line-1]) {
		e.NewText = ""
		e.Range = Range{}
		return
	}

	if e.Range.End.Line > len(lines) {
		e.Range.End.Line = len(lines)
		e.Range.End.Character = len(lines[e.Range.End.Line-1])
		return
	}

	maxEndLineNo := int(math.Max(0, float64(e.Range.End.Line-1)))
	if e.Range.End.Character >= len(lines[maxEndLineNo]) {
		e.Range.End.Character = len(lines[maxEndLineNo])
		return
	}

	if e.Range.Start.Line > e.Range.End.Line ||
		e.Range.Start.Line == e.Range.End.Line && e.Range.Start.Character > e.Range.End.Character {

		e.NewText = ""
		e.Range = Range{}
		return
	}
}

type WorkspaceEdit struct {
	/**
	 * Holds changes to existing resources.
	 */
	Changes map[string][]TextEdit
}
