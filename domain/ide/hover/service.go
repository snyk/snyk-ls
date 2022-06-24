package hover

import (
	"fmt"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/domain/snyk/issues"
	"github.com/snyk/snyk-ls/internal/observability/ux"
	"github.com/snyk/snyk-ls/internal/uri"
)

type Service struct {
	hovers       map[sglsp.DocumentURI][]Hover[Context]
	hoverIndexes map[string]bool
	hoverChan    chan DocumentHovers
	stopChannel  chan bool
	mutex        *sync.Mutex
	analytics    ux.Analytics
}

func NewService(analytics ux.Analytics) *Service {
	s := &Service{}
	s.hovers = map[sglsp.DocumentURI][]Hover[Context]{}
	s.hoverIndexes = map[string]bool{}
	s.hoverChan = make(chan DocumentHovers, 100)
	s.stopChannel = make(chan bool, 100)
	s.mutex = &sync.Mutex{}
	s.analytics = analytics
	go s.createHoverListener()
	return s
}

func (s *Service) validateAndExtractMessage(hover Hover[Context], pos sglsp.Position) (message string) {
	if s.isHoverForPosition(hover, pos) {
		message = hover.Message
	}

	return message
}

func (s *Service) isHoverForPosition(hover Hover[Context], pos sglsp.Position) bool {
	return hover.Range.Start.Line < pos.Line && hover.Range.End.Line > pos.Line ||
		(hover.Range.Start.Line == pos.Line &&
			hover.Range.Start.Character <= pos.Character &&
			hover.Range.End.Character >= pos.Character)
}

func (s *Service) registerHovers(result DocumentHovers) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for _, newHover := range result.Hover {
		key := result.Uri
		hoverIndex := uri.PathFromUri(key) + fmt.Sprintf("%v%v", newHover.Range, newHover.Id)

		if !s.hoverIndexes[hoverIndex] {
			s.hovers[key] = append(s.hovers[key], newHover)
			s.hoverIndexes[hoverIndex] = true
		}
	}
}

func (s *Service) DeleteHover(documentUri sglsp.DocumentURI) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.hovers, documentUri)
	for key := range s.hoverIndexes {
		document := uri.PathFromUri(documentUri)
		if strings.Contains(key, document) {
			delete(s.hoverIndexes, key)
		}
	}
}

func (s *Service) Channel() chan DocumentHovers {
	return s.hoverChan
}

func (s *Service) ClearAllHovers() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.stopChannel <- true
	s.hovers = map[sglsp.DocumentURI][]Hover[Context]{}
	s.hoverIndexes = map[string]bool{}
}

func (s *Service) GetHover(fileUri sglsp.DocumentURI, pos sglsp.Position) Result {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var hoverMessage string
	for _, hover := range s.hovers[fileUri] {
		if s.isHoverForPosition(hover, pos) {
			s.trackHoverDetails(hover)
			hoverMessage += hover.Message
		}
	}

	return Result{
		Contents: MarkupContent{
			Kind:  "markdown",
			Value: hoverMessage,
		},
	}
}

func (s *Service) trackHoverDetails(hover Hover[Context]) {
	switch hover.Context.(type) {
	case issues.Issue:
		issue := hover.Context.(issues.Issue)
		s.analytics.IssueHoverIsDisplayed(ux.NewIssueHoverIsDisplayedProperties(issue))
	default:
		log.Warn().Msgf("unknown context for hover %v", hover)
	}
}

func (s *Service) createHoverListener() {
	// cleanup before start
	for {
		select {
		case <-s.stopChannel:
			continue
		default:
		}
		break
	}
	for {
		select {
		case result := <-s.hoverChan:
			log.Trace().
				Str("method", "createHoverListener").
				Str("uri", string(result.Uri)).
				Msg("reading hover from chan.")

			s.registerHovers(result)
			continue
		case <-s.stopChannel:
		}
		break
	}
	// cleanup on shutdown
	for {
		select {
		case <-s.hoverChan:
			continue
		default:
		}
		break
	}
}

func (s *Service) SetAnalytics(analytics ux.Analytics) {
	s.analytics = analytics
}
