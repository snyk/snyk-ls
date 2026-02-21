/*
 * © 2026 Snyk Limited
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

package treeview

import (
	"fmt"
	"sync"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
)

var _ Disposable = (*TreeScanStateEmitter)(nil)

type Disposable interface {
	Dispose()
}

// TreeScanStateEmitter adapts the ScanStateChangeEmitter interface to emit tree view HTML.
// It is registered alongside the summary emitter in the composite emitter.
//
// Emit is non-blocking: it stores the latest snapshot and signals a background
// goroutine to perform the expensive BuildTree + RenderTreeView work. If
// multiple snapshots arrive before rendering completes, only the most recent
// one is processed, avoiding pipeline stalls in the ScanStateAggregator.
type TreeScanStateEmitter struct {
	mu       sync.Mutex
	notifier notification.Notifier
	c        *config.Config
	builder  *TreeBuilder
	renderer *TreeHtmlRenderer

	pendingState *scanstates.StateSnapshot
	renderSignal chan struct{}
	done         chan struct{}
	disposeOnce  sync.Once
}

// NewTreeScanStateEmitter creates a new TreeScanStateEmitter.
func NewTreeScanStateEmitter(c *config.Config, n notification.Notifier) (*TreeScanStateEmitter, error) {
	renderer, err := NewTreeHtmlRenderer(c)
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize TreeHtmlRenderer: %w", err)
	}

	e := &TreeScanStateEmitter{
		notifier:     n,
		c:            c,
		builder:      NewTreeBuilder(GlobalExpandState()),
		renderer:     renderer,
		renderSignal: make(chan struct{}, 1),
		done:         make(chan struct{}),
	}
	go e.renderLoop()
	return e, nil
}

// Emit stores the latest scan state snapshot and signals the render loop.
// It returns immediately so the ScanStateAggregator pipeline is not blocked.
func (e *TreeScanStateEmitter) Emit(state scanstates.StateSnapshot) {
	e.mu.Lock()
	e.pendingState = &state
	e.mu.Unlock()

	select {
	case e.renderSignal <- struct{}{}:
	case <-e.done:
	default:
	}
}

// Dispose stops the background render goroutine. Safe to call multiple times.
func (e *TreeScanStateEmitter) Dispose() {
	e.disposeOnce.Do(func() { close(e.done) })
}

func (e *TreeScanStateEmitter) renderLoop() {
	for {
		select {
		case <-e.done:
			return
		case <-e.renderSignal:
			e.renderPending()
		}
	}
}

func (e *TreeScanStateEmitter) renderPending() {
	e.mu.Lock()
	state := e.pendingState
	e.pendingState = nil
	e.mu.Unlock()

	if state == nil {
		return
	}

	e.builder.SetProductScanStates(state.ProductScanStates)
	e.builder.SetProductScanErrors(state.ProductScanErrors)
	e.builder.SetIssueViewOptions(e.c.IssueViewOptions())

	ws := e.c.Workspace()
	var data TreeViewData
	if ws != nil {
		data = e.builder.BuildTree(ws)
	}
	data.FilterState = TreeViewFilterState{
		SeverityFilter:   e.c.FilterSeverity(),
		IssueViewOptions: e.c.IssueViewOptions(),
	}

	html := e.renderer.RenderTreeView(data)
	e.notifier.Send(types.TreeView{TreeViewHtml: html, TotalIssues: data.TotalIssues})
}
