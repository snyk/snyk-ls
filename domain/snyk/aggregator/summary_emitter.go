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

package aggregator

import (
	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
)

type ScanStateChangeEmitter interface {
	Emit(aggregator StateAggregator)
}

type SummaryEmitter struct {
	notifier notification.Notifier
	c        *config.Config
}

func NewSummaryEmitter(n notification.Notifier, c *config.Config) *SummaryEmitter {
	return &SummaryEmitter{
		notifier: n,
		c:        c,
	}
}

func (s *SummaryEmitter) Emit(aggregator StateAggregator) {
	generatedHtml := "<html>test</html>"
	s.notifier.Send(types.ScanSummary{ScanSummary: generatedHtml})
}
