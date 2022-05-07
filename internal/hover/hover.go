package hover

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/lsp"

	sglsp "github.com/sourcegraph/go-lsp"
)

var hovers = map[sglsp.DocumentURI][]lsp.HoverDetails{}
var hoverIndexes = map[string]bool{}

var hoverChan = make(chan lsp.Hover, 100)
var stopChannel = make(chan bool, 100)
var mutex = &sync.Mutex{}
var logger = environment.Logger

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

func Channel() chan lsp.Hover {
	return hoverChan
}

func ClearAllHovers() {
	mutex.Lock()
	defer mutex.Unlock()
	stopChannel <- true
	hovers = map[sglsp.DocumentURI][]lsp.HoverDetails{}
	hoverIndexes = map[string]bool{}
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
			logger.
				WithField("method", "CreateHoverListener").
				WithField("uri", string(result.Uri)).
				Trace(context.Background(), "reading hover from chan")

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
