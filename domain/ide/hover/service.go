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

package hover

import (
	"fmt"
	"strings"
	"sync"

	"github.com/snyk/snyk-ls/application/config"
	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
)

type Service interface {
	DeleteHover(path string)
	Channel() chan DocumentHovers
	ClearAllHovers()
	GetHover(path string, pos snyk.Position) Result
	SetAnalytics(analytics ux2.Analytics)
}

type DefaultHoverService struct {
	hovers       map[string][]Hover[Context]
	hoverIndexes map[string]bool
	hoverChan    chan DocumentHovers
	mutex        *sync.Mutex
	analytics    ux2.Analytics
	c            *config.Config
}

func NewDefaultService(c *config.Config, analytics ux2.Analytics) Service {
	s := &DefaultHoverService{}
	s.hovers = map[string][]Hover[Context]{}
	s.hoverIndexes = map[string]bool{}
	s.hoverChan = make(chan DocumentHovers, 100)
	s.mutex = &sync.Mutex{}
	s.analytics = analytics
	s.c = c
	go s.createHoverListener()
	return s
}

func (s *DefaultHoverService) isHoverForPosition(hover Hover[Context], pos snyk.Position) bool {
	hoverRange := hover.Range
	posRange := snyk.Range{Start: pos, End: pos}
	overlaps := hoverRange.Overlaps(posRange)
	s.c.Logger().Trace().Str("method", "isHoverForPosition").Msgf("hover: %v, pos: %v, overlaps: %v", hoverRange, pos, overlaps)
	return overlaps
}

func (s *DefaultHoverService) registerHovers(result DocumentHovers) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for _, newHover := range result.Hover {
		key := result.Path
		hoverIndex := key + fmt.Sprintf("%v%v", newHover.Range, newHover.Id)

		if !s.hoverIndexes[hoverIndex] {
			s.c.Logger().Debug().
				Str("method", "registerHovers").
				Str("hoverIndex", hoverIndex).
				Msg("registering hover")

			s.hovers[key] = append(s.hovers[key], newHover)
			s.hoverIndexes[hoverIndex] = true
		}
	}
}

func (s *DefaultHoverService) DeleteHover(path string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.hovers, path)
	for key := range s.hoverIndexes {
		document := path
		if strings.Contains(key, document) {
			s.c.Logger().Debug().
				Str("method", "DeleteHover").
				Str("key", key).
				Str("document", document).
				Msg("deleting hover")

			delete(s.hoverIndexes, key)
		}
	}
}

func (s *DefaultHoverService) Channel() chan DocumentHovers {
	return s.hoverChan
}

func (s *DefaultHoverService) ClearAllHovers() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.hovers = map[string][]Hover[Context]{}
	s.hoverIndexes = map[string]bool{}
}

func (s *DefaultHoverService) GetHover(path string, pos snyk.Position) Result {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var hoverMessage string
	for _, hover := range s.hovers[path] {
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

func (s *DefaultHoverService) trackHoverDetails(hover Hover[Context]) {
	switch hover.Context.(type) {
	case snyk.Issue:
		issue := hover.Context.(snyk.Issue)
		s.analytics.IssueHoverIsDisplayed(NewIssueHoverIsDisplayedProperties(issue))
	default:
		s.c.Logger().Warn().Msgf("unknown context for hover %v", hover)
	}
}

func (s *DefaultHoverService) createHoverListener() {
	for {
		result := <-s.hoverChan
		s.c.Logger().Trace().
			Str("method", "createHoverListener").
			Str("uri", result.Path).
			Msg("reading hover from chan.")

		s.registerHovers(result)
	}
}

func (s *DefaultHoverService) SetAnalytics(analytics ux2.Analytics) {
	s.analytics = analytics
}
