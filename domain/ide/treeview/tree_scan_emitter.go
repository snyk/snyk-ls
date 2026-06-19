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

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"

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
	conf     configuration.Configuration
	logger   *zerolog.Logger
	builder  *TreeBuilder
	renderer *TreeHtmlRenderer

	pendingState *scanstates.StateSnapshot
	renderSignal chan struct{}
	done         chan struct{}
	disposeOnce  sync.Once
}

// NewTreeScanStateEmitter creates a new TreeScanStateEmitter.
func NewTreeScanStateEmitter(conf configuration.Configuration, logger *zerolog.Logger, n notification.Notifier) (*TreeScanStateEmitter, error) {
	renderer, err := NewTreeHtmlRenderer(logger)
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize TreeHtmlRenderer: %w", err)
	}

	e := &TreeScanStateEmitter{
		notifier:     n,
		conf:         conf,
		logger:       logger,
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

	ws := config.GetWorkspace(e.conf)
	var data TreeViewData
	if ws != nil {
		data = e.builder.BuildTree(ws)
	}
	data.FilterState = ResolveFilterState(e.conf, ws)

	html := e.renderer.RenderTreeView(data)
	e.notifier.Send(types.TreeView{TreeViewHtml: html, TotalIssues: data.TotalIssues})
}

// ResolveFilterState resolves the toolbar's severity + issue-view state. The tree's
// filter toolbar is workspace-wide but the tree shows every open folder, each
// filtered by its own per-folder config (UserFolderKey > remote > user-global >
// default) — the same source the issue filtering uses. So the toolbar reflects
// the aggregate across all open folders: a severity is shown/hidden when every
// folder agrees, or marked "mixed" when they disagree. Falls back to the global
// value when there is no folder or resolver. (IDE-1866 / IDE-1996)
//
// Shared by the push path (TreeScanStateEmitter) and the pull path
// (snyk.getTreeView) so a tree fetched on panel-open matches one pushed on a scan.
func ResolveFilterState(conf configuration.Configuration, ws types.Workspace) TreeViewFilterState {
	severity := config.GetFilterSeverity(conf)
	issueView := config.GetIssueViewOptions(conf)
	var mixed MixedSeverity

	if ws != nil {
		var severities []types.SeverityFilter
		var firstFC *types.FolderConfig
		for _, f := range ws.Folders() {
			fc := f.FolderConfigReadOnly()
			if fc == nil || fc.ConfigResolver == nil {
				continue
			}
			if firstFC == nil {
				firstFC = fc
			}
			severities = append(severities, fc.ConfigResolver.FilterSeverityForFolder(fc))
		}
		if len(severities) > 0 {
			severity, mixed = aggregateSeverityFilters(severities)
		}
		if firstFC != nil {
			issueView = firstFC.ConfigResolver.IssueViewOptionsForFolder(firstFC)
		}
	}

	return TreeViewFilterState{
		SeverityFilter:   severity,
		MixedSeverity:    mixed,
		IssueViewOptions: issueView,
	}
}

// aggregateSeverityFilters reduces per-folder severity filters to a single
// toolbar state plus a per-severity "mixed" marker. When all folders agree the
// agreed value is returned; where they disagree the severity is marked mixed
// (the returned bool for that severity is unspecified — the mixed marker wins in
// rendering).
func aggregateSeverityFilters(filters []types.SeverityFilter) (types.SeverityFilter, MixedSeverity) {
	agg := filters[0]
	var mixed MixedSeverity
	for _, f := range filters[1:] {
		if f.Critical != agg.Critical {
			mixed.Critical = true
		}
		if f.High != agg.High {
			mixed.High = true
		}
		if f.Medium != agg.Medium {
			mixed.Medium = true
		}
		if f.Low != agg.Low {
			mixed.Low = true
		}
	}
	return agg, mixed
}
