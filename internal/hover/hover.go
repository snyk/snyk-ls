package hover

import (
	"sync"

	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/lsp"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"
)

var hovers = map[string][]lsp.HoverDetails{}
var hoverChan = make(chan lsp.Hover, 4)
var mutex = &sync.Mutex{}

func Channel() chan lsp.Hover {
	return hoverChan
}

func ClearAllHovers() {
	hovers = map[string][]lsp.HoverDetails{}
}

func GetHover(fileUri sglsp.DocumentURI, pos sglsp.Position) lsp.HoverResult {
	mutex.Lock()
	defer mutex.Unlock()

	key := uri.PathFromUri(fileUri)
	var hoverMessage string

	for _, hover := range hovers[key] {
		if hover.Range.Start.Line < pos.Line && hover.Range.End.Line > pos.Line ||
			(hover.Range.Start.Line == pos.Line &&
				hover.Range.Start.Character <= pos.Character &&
				hover.Range.End.Character >= pos.Character) {
			hoverMessage += hover.Message
		}
	}

	return lsp.HoverResult{
		Contents: lsp.MarkupContent{
			Kind:  "markdown",
			Value: hoverMessage,
		},
	}
}

func CreateHoverListener() {
	for {
		select {
		case result := <-hoverChan:
			log.Trace().
				Str("method", "CreateHoverListener").
				Str("uri", string(result.Uri)).
				Msg("reading hover from chan.")

			mutex.Lock()
			for _, h := range result.Hover {
				key := uri.PathFromUri(result.Uri)
				hovers[key] = append(hovers[key], h)
			}
			mutex.Unlock()
		}
	}
}
