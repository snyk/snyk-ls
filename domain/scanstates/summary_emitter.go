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

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
)

//go:generate go tool github.com/golang/mock/mockgen -source=summary_emitter.go -destination=scan_state_change_emitter_mock.go -package=scanstates

type ScanStateChangeEmitter interface {
	Emit(aggregator StateSnapshot)
}

type Emitter struct {
	notifier notification.Notifier
	renderer *HtmlRenderer
}

func NewSummaryEmitter(conf configuration.Configuration, logger *zerolog.Logger, n notification.Notifier) *Emitter {
	emitter := &Emitter{
		notifier: n,
	}

	renderer, err := NewHtmlRenderer(conf, logger)
	if err != nil {
		panic(fmt.Sprintf("Couldn't initialize HtmlRenderer: %v", err))
	}
	emitter.renderer = renderer

	return emitter
}

func (s *Emitter) Emit(state StateSnapshot) {
	generatedHtml := s.renderer.GetSummaryHtml(state)
	s.notifier.Send(types.ScanSummary{ScanSummary: generatedHtml})
}
