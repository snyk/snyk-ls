package code

import (
	"fmt"
	"path/filepath"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/files"
	"github.com/snyk/snyk-ls/internal/uri"
)

type dataflowElement struct {
	position  int
	filePath  string
	flowRange snyk.Range
	content   string
}

func (d dataflowElement) String() string {
	return fmt.Sprintf("pos=%d, filePath=%s, flowRange %s, content=%s", d.position, d.filePath, d.flowRange.String(), d.content)
}

func (d *dataflowElement) toMarkDown() (markdown string) {
	fileName := filepath.Base(d.filePath)
	fileURI := uri.PathToUri(d.filePath)
	line := d.flowRange.Start.Line + 1 // range is 0-based
	fileUtil := files.New()
	if d.content == "" {
		var err error
		d.content, err = fileUtil.GetLineOfCode(d.filePath, line)
		if err != nil {
			log.Warn().Str("method", "code.dataflow.toMarkdown").Err(err).Msg("cannot load line content from file")
		}
	}
	markdown = fmt.Sprintf(
		"%d. [%s:%d](%s) `%s`\n\n",
		d.position,
		fileName,
		line,
		uri.AddRangeToUri(fileURI, uri.Range{
			StartLine: d.flowRange.Start.Line,
			EndLine:   d.flowRange.End.Line,
			StartChar: d.flowRange.Start.Character,
			EndChar:   d.flowRange.End.Character,
		}),
		d.content,
	)
	return markdown
}

func (d *dataflowElement) toCommand() snyk.Command {
	command := snyk.Command{
		Title: fmt.Sprintf(
			"Snyk Data Flow (%d) %s:%d",
			d.position,
			filepath.Base(d.filePath),
			d.flowRange.Start.Line+1,
		),
		Command:   snyk.NavigateToRangeCommand,
		Arguments: []interface{}{d.filePath, d.flowRange},
	}
	return command
}
