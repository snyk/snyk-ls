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
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
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
	data.FilterState = e.filterState(ws)

	html := e.renderer.RenderTreeView(data)
	e.notifier.Send(types.TreeView{TreeViewHtml: html, TotalIssues: data.TotalIssues})
}

// filterState resolves the toolbar's filter state for this emitter's config.
// Thin wrapper over BuildFilterState so the scan-emitter and the snyk.getTreeView
// command share one implementation (and therefore render the same toolbar).
func (e *TreeScanStateEmitter) filterState(ws types.Workspace) TreeViewFilterState {
	return BuildFilterState(e.conf, ws)
}

// BuildFilterState resolves the toolbar's severity, risk-score and issue-view
// state. The filter toolbar is workspace-wide but the tree shows every open
// folder, each filtered by its own per-folder config (UserFolderKey > remote >
// user-global > default) — the same source the issue filtering uses. So the
// toolbar reflects the aggregate across all open folders: a value is shown when
// every folder agrees, or marked "mixed" when they disagree. Falls back to the
// global value when there is no folder or resolver.
//
// Risk score and issue-view options are each gated by a feature flag — the same
// flags the server-side filter checks (see folder.buildFilterContext). A folder's
// value is only folded into the aggregate when its flag is on, so a folder that
// doesn't filter on that dimension doesn't register as "disagreeing". The section
// is shown when the flag is on for at least one open folder.
//
// Shared by TreeScanStateEmitter.filterState and the snyk.getTreeView command;
// both render paths must produce the same toolbar.
func BuildFilterState(conf configuration.Configuration, ws types.Workspace) TreeViewFilterState {
	severity := config.GetFilterSeverity(conf)
	issueView := config.GetIssueViewOptions(conf)
	var mixedSeverity MixedSeverity
	var mixedIssueView MixedIssueViewOptions
	var riskScore int
	var riskScoreMixed bool
	var riskScoreEnabled, issueViewEnabled bool

	if ws != nil {
		var severities []types.SeverityFilter
		var issueViews []types.IssueViewOptions
		var riskScores []int
		for _, f := range ws.Folders() {
			fc := f.FolderConfigReadOnly()
			if fc == nil || fc.ConfigResolver == nil {
				continue
			}
			severities = append(severities, fc.ConfigResolver.FilterSeverityForFolder(fc))

			if featureflag.UseOsTestWorkflow(fc) {
				riskScoreEnabled = true
				riskScores = append(riskScores, fc.ConfigResolver.RiskScoreThresholdForFolder(fc))
			}
			if fc.GetFeatureFlag(featureflag.SnykCodeConsistentIgnores) {
				issueViewEnabled = true
				issueViews = append(issueViews, fc.ConfigResolver.IssueViewOptionsForFolder(fc))
			}
		}
		if len(severities) > 0 {
			severity, mixedSeverity = aggregateSeverityFilters(severities)
		}
		if len(issueViews) > 0 {
			issueView, mixedIssueView = aggregateIssueViewOptions(issueViews)
		}
		if len(riskScores) > 0 {
			riskScore, riskScoreMixed = aggregateRiskScores(riskScores)
		}
	}

	return TreeViewFilterState{
		SeverityFilter:          severity,
		MixedSeverity:           mixedSeverity,
		IssueViewOptions:        issueView,
		RiskScoreThreshold:      riskScore,
		RiskScoreMixed:          riskScoreMixed,
		MixedIssueViewOptions:   mixedIssueView,
		RiskScoreEnabled:        riskScoreEnabled,
		IssueViewOptionsEnabled: issueViewEnabled,
		ShowFilterPopover:       riskScoreEnabled || issueViewEnabled,
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

// aggregateIssueViewOptions reduces per-folder issue-view options to a single
// toolbar state plus a per-option "mixed" marker, analogous to
// aggregateSeverityFilters.
func aggregateIssueViewOptions(opts []types.IssueViewOptions) (types.IssueViewOptions, MixedIssueViewOptions) {
	agg := opts[0]
	var mixed MixedIssueViewOptions
	for _, o := range opts[1:] {
		if o.OpenIssues != agg.OpenIssues {
			mixed.OpenIssues = true
		}
		if o.IgnoredIssues != agg.IgnoredIssues {
			mixed.IgnoredIssues = true
		}
	}
	return agg, mixed
}

// aggregateRiskScores reduces per-folder risk-score thresholds to a single
// toolbar value plus a "mixed" marker (true when the folders disagree). When
// mixed, the returned value is the first folder's — rendering shows "Mixed"
// instead.
func aggregateRiskScores(scores []int) (int, bool) {
	agg := scores[0]
	for _, s := range scores[1:] {
		if s != agg {
			return agg, true
		}
	}
	return agg, false
}
