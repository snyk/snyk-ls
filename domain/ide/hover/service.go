package hover

import (
	"fmt"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/internal/uri"
)

var hovers = map[sglsp.DocumentURI][]Hover[Context]{}
var hoverIndexes = map[string]bool{}

var hoverChan = make(chan DocumentHovers, 100)
var stopChannel = make(chan bool, 100)
var mutex = &sync.Mutex{}

func validateAndExtractMessage(hover Hover[Context], pos sglsp.Position) string {
	var message string
	if hover.Range.Start.Line < pos.Line && hover.Range.End.Line > pos.Line ||
		(hover.Range.Start.Line == pos.Line &&
			hover.Range.Start.Character <= pos.Character &&
			hover.Range.End.Character >= pos.Character) {
		message = hover.Message
	}

	return message
}

func registerHovers(result DocumentHovers) {
	mutex.Lock()
	defer mutex.Unlock()

	for _, newHover := range result.Hover {
		key := result.Uri
		hoverIndex := uri.PathFromUri(key) + fmt.Sprintf("%v%v", newHover.Range, newHover.Id)

		if !hoverIndexes[hoverIndex] {
			hovers[key] = append(hovers[key], newHover)
			hoverIndexes[hoverIndex] = true
		}
	}
}

func DeleteHover(documentUri sglsp.DocumentURI) {
	mutex.Lock()
	defer mutex.Unlock()

	delete(hovers, documentUri)
	for key := range hoverIndexes {
		document := uri.PathFromUri(documentUri)
		if strings.Contains(key, document) {
			delete(hoverIndexes, key)
		}
	}
}

func Channel() chan DocumentHovers {
	return hoverChan
}

func ClearAllHovers() {
	mutex.Lock()
	defer mutex.Unlock()
	stopChannel <- true
	hovers = map[sglsp.DocumentURI][]Hover[Context]{}
	hoverIndexes = map[string]bool{}
}

func GetHover(fileUri sglsp.DocumentURI, pos sglsp.Position) Result {
	mutex.Lock()
	defer mutex.Unlock()

	var hoverMessage string
	for _, hover := range hovers[fileUri] {
		hoverMessage += validateAndExtractMessage(hover, pos)
	}

	return Result{
		Contents: MarkupContent{
			Kind:  "markdown",
			Value: hoverMessage,
		},
	}
}

func CreateHoverListener() {
	// cleanup before start
	for {
		select {
		case <-stopChannel:
			continue
		default:
		}
		break
	}
	for {
		select {
		case result := <-hoverChan:
			log.Trace().
				Str("method", "CreateHoverListener").
				Str("uri", string(result.Uri)).
				Msg("reading hover from chan.")

			registerHovers(result)
			continue
		case <-stopChannel:
		}
		break
	}
	// cleanup on shutdown
	for {
		select {
		case <-hoverChan:
			continue
		default:
		}
		break
	}
}
