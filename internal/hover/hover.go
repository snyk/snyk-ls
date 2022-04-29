package hover

import (
	"fmt"
	"sync"

	"github.com/snyk/snyk-ls/lsp"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"
)

var hovers = map[sglsp.DocumentURI][]lsp.HoverDetails{}
var hoverIndexes = make(map[sglsp.DocumentURI]map[string]bool)

var hoverChan = make(chan lsp.Hover, 4)
var mutex = &sync.Mutex{}

func validateAndExtractMessage(hover lsp.HoverDetails, pos sglsp.Position) string {
	var message string
	if hover.Range.Start.Line < pos.Line && hover.Range.End.Line > pos.Line ||
		(hover.Range.Start.Line == pos.Line &&
			hover.Range.Start.Character <= pos.Character &&
			hover.Range.End.Character >= pos.Character) {
		message = hover.Message
	}

	return message
}

func registerHovers(result lsp.Hover) {
	mutex.Lock()
	for _, newHover := range result.Hover {
		key := result.Uri
		hoverIndex := fmt.Sprintf("%v", newHover.Range) + newHover.Id

		if !hoverIndexes[key][hoverIndex] {
			hovers[key] = append(hovers[key], newHover)

			indexMap := map[string]bool{}
			indexMap[hoverIndex] = true
			hoverIndexes[key] = indexMap
		}
	}
	mutex.Unlock()
}

func DeleteHover(documentUri sglsp.DocumentURI) {
	delete(hovers, documentUri)
	delete(hoverIndexes, documentUri)
}

func Channel() chan lsp.Hover {
	return hoverChan
}

func ClearAllHovers() {
	hovers = map[sglsp.DocumentURI][]lsp.HoverDetails{}
	hoverIndexes = make(map[sglsp.DocumentURI]map[string]bool)
}

func GetHover(fileUri sglsp.DocumentURI, pos sglsp.Position) lsp.HoverResult {
	mutex.Lock()
	defer mutex.Unlock()

	var hoverMessage string
	for _, hover := range hovers[fileUri] {
		hoverMessage += validateAndExtractMessage(hover, pos)
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
		result := <-hoverChan
		log.Trace().
			Str("method", "CreateHoverListener").
			Str("uri", string(result.Uri)).
			Msg("reading hover from chan.")

		registerHovers(result)
	}
}
