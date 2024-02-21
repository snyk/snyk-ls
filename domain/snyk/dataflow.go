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

package snyk

import (
	"fmt"
	"path/filepath"

	"github.com/snyk/snyk-ls/internal/uri"
)

type DataFlowElement struct {
	Position  int
	FilePath  string
	FlowRange Range
	Content   string
}

func (d *DataFlowElement) String() string {
	return fmt.Sprintf("Position=%d, FilePath=%s, FlowRange %s, Content=%s", d.Position, d.FilePath, d.FlowRange.String(), d.Content)
}

func (d *DataFlowElement) ToMarkDown() (markdown string) {
	fileName := filepath.Base(d.FilePath)
	fileURI := uri.PathToUri(d.FilePath)
	line := d.FlowRange.Start.Line + 1 // range is 0-based
	markdown = fmt.Sprintf(
		"%d. [%s:%d](%s) `%s`\n\n",
		d.Position,
		fileName,
		line,
		uri.AddRangeToUri(fileURI, uri.Range{
			StartLine: d.FlowRange.Start.Line,
			EndLine:   d.FlowRange.End.Line,
			StartChar: d.FlowRange.Start.Character,
			EndChar:   d.FlowRange.End.Character,
		}),
		d.Content,
	)
	return markdown
}
