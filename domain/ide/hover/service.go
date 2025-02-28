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
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

type Service interface {
	DeleteHover(p product.Product, path types.FilePath)
	Channel() chan DocumentHovers
	ClearAllHovers()
	GetHover(path types.FilePath, pos types.Position) Result
}

type hoversByProduct map[product.Product][]Hover[Context]

type DefaultHoverService struct {
	hoversByFilePath map[types.FilePath]hoversByProduct
	hoverIndexes     map[string]bool
	hoverChan        chan DocumentHovers
	mutex            *sync.RWMutex
	c                *config.Config
}

func NewDefaultService(c *config.Config) Service {
	s := &DefaultHoverService{}
	s.hoversByFilePath = make(map[types.FilePath]hoversByProduct)
	s.hoverIndexes = make(map[string]bool)
	s.hoverChan = make(chan DocumentHovers, 10000)
	s.mutex = &sync.RWMutex{}
	s.c = c
	go s.createHoverListener()
	return s
}

func (s *DefaultHoverService) isHoverForPosition(hover Hover[Context], pos types.Position) bool {
	hoverRange := hover.Range
	posRange := types.Range{Start: pos, End: pos}
	overlaps := hoverRange.Overlaps(posRange)
	s.c.Logger().Trace().Str("method", "isHoverForPosition").Msgf("hover: %v, pos: %v, overlaps: %v", hoverRange, pos, overlaps)
	return overlaps
}

func (s *DefaultHoverService) registerHovers(result DocumentHovers) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for _, newHover := range result.Hover {
		path := result.Path
		p := result.Product
		hoverIndex := fmt.Sprintf("%s%v%v%s", path, newHover.Range, newHover.Id, p.ToProductCodename())

		if !s.hoverIndexes[hoverIndex] {
			s.c.Logger().Debug().
				Str("method", "registerHovers").
				Str("hoverIndex", hoverIndex).
				Msg("registering hover")
			if _, exists := s.hoversByFilePath[path]; !exists {
				s.hoversByFilePath[path] = make(hoversByProduct)
			}
			s.hoversByFilePath[path][p] = append(s.hoversByFilePath[path][p], newHover)
			s.hoverIndexes[hoverIndex] = true
		}
	}
}

func (s *DefaultHoverService) DeleteHover(p product.Product, path types.FilePath) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if _, exists := s.hoversByFilePath[path]; exists {
		delete(s.hoversByFilePath[path], p)
	}
	for indexKey := range s.hoverIndexes {
		document := string(path)
		if strings.Contains(indexKey, document) && strings.Contains(indexKey, p.ToProductCodename()) {
			s.c.Logger().Debug().
				Str("method", "DeleteHover").
				Str("key", indexKey).
				Str("document", document).
				Msg("deleting hover")

			delete(s.hoverIndexes, indexKey)
		}
	}
}

func (s *DefaultHoverService) Channel() chan DocumentHovers {
	return s.hoverChan
}

func (s *DefaultHoverService) ClearAllHovers() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.hoversByFilePath = map[types.FilePath]hoversByProduct{}
	s.hoverIndexes = map[string]bool{}
}

func (s *DefaultHoverService) GetHover(path types.FilePath, pos types.Position) Result {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var hoverMessage string
	for _, hovers := range s.hoversByFilePath[path] {
		for _, hover := range hovers {
			if s.isHoverForPosition(hover, pos) {
				hoverMessage += hover.Message
			}
		}
	}

	return Result{
		Contents: MarkupContent{
			Kind:  "markdown",
			Value: hoverMessage,
		},
	}
}

func (s *DefaultHoverService) createHoverListener() {
	for {
		result := <-s.hoverChan
		s.c.Logger().Trace().
			Str("method", "createHoverListener").
			Str("uri", string(result.Path)).
			Msg("reading hover from chan.")

		s.registerHovers(result)
	}
}
