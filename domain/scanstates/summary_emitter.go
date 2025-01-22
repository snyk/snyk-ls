/*
 * © 2025 Snyk Limited
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

package scanstates

import (
	"fmt"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
)

type ScanStateChangeEmitter interface {
	Emit(aggregator Aggregator)
}

type Emitter struct {
	notifier notification.Notifier
	c        *config.Config
	renderer *HtmlRenderer
}

func NewSummaryEmitter(n notification.Notifier, c *config.Config) *Emitter {
	emitter := &Emitter{
		notifier: n,
		c:        c,
	}

	renderer, err := NewHtmlRenderer(c)
	if err != nil {
		panic(fmt.Sprintf("Couldn't initialize HtmlRenderer: %v", err))
	}
	emitter.renderer = renderer
	return emitter
}

func (s *Emitter) Emit(aggregator Aggregator) {
	generatedHtml := s.renderer.GetSummaryHtml(aggregator)
	go s.notifier.Send(types.ScanSummary{ScanSummary: generatedHtml})
}
