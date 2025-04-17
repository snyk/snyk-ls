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

package lsui

import (
	"math"
	"sync"

	"github.com/snyk/go-application-framework/pkg/ui"

	"github.com/snyk/snyk-ls/internal/progress"
)

type lsProgressBar struct {
	tracker  *progress.Tracker
	title    string
	message  string
	progress *int
	m        sync.Mutex
}

func newLSProgressBar(title string) *lsProgressBar {
	tracker := progress.NewTracker(true)
	return &lsProgressBar{
		tracker: tracker,
		title:   title,
	}
}

func newTestLSProgressBar(tracker *progress.Tracker, title string) *lsProgressBar {
	return &lsProgressBar{
		tracker: tracker,
		title:   title,
	}
}

func (p *lsProgressBar) sendUpdate() {
	if p.progress == nil {
		// We won't have begun until we know the progress "type" (infinite or a percentage),
		// as the progress tracker needs to know if it is quantifiable or not when beginning
		return
	}
	p.tracker.ReportWithMessage(*p.progress, p.message)
}

func (p *lsProgressBar) UpdateProgress(progress float64) error {
	p.m.Lock()
	defer p.m.Unlock()
	if p.progress == nil /* Haven't begun */ {
		if progress == ui.InfiniteProgress {
			p.tracker.BeginUnquantifiableLength(p.title, p.message)
		} else {
			p.tracker.BeginWithMessage(p.title, p.message)
		}
	}

	p.progress = new(int)
	*p.progress = int(math.Floor(math.Min(progress, 1) * 100))
	p.sendUpdate()
	return nil
}

func (p *lsProgressBar) SetMessage(message string) {
	p.m.Lock()
	defer p.m.Unlock()
	p.message = message
	p.sendUpdate()
}

func (p *lsProgressBar) Clear() error {
	p.m.Lock()
	defer p.m.Unlock()
	p.tracker.End()
	return nil
}
