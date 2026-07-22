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

// This file contains race-detector tests for CodeActionsService. Run with:
//
//	go test -race ./application/codeaction/...
package codeaction_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/codeaction"
	"github.com/snyk/snyk-ls/application/watcher"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/mock_snyk"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/testutil/workspaceutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

// TestActionsCache_NoDataRace verifies that concurrent writes to actionsCache
// (via GetCodeActions → cacheCodeAction) and concurrent reads/deletes (via
// ResolveCodeAction) do not produce a data race.
//
// Pattern:
//   - One writer goroutine repeatedly calls GetCodeActions with fresh issue sets
//     (each cycle produces a brand-new issue list so no CodeAction is shared
//     between writer iterations — only actionsCache itself is shared).
//   - Many reader goroutines call ResolveCodeAction on actions that were
//     pre-cached by the initial serial call.
//
// Without actionsCacheMu the Go race detector reports "concurrent map
// read/write"; with the mutex the test completes cleanly.
func TestActionsCache_NoDataRace(t *testing.T) {
	engine := testutil.UnitTest(t)
	r := exampleRange
	uriPath := documentUriExample
	path := uri.PathFromUri(uriPath)

	_, _ = workspaceutil.SetupWorkspace(t, engine, types.FilePath("/path/to"))

	// issueGen generates a brand-new issue list on each call so that no
	// CodeAction object is shared between goroutines (only actionsCache is shared).
	const batchSize = 10
	var callCount atomic.Int32
	issueGen := func() []types.Issue {
		n := int(callCount.Add(1))
		issues := make([]types.Issue, batchSize)
		for i := range batchSize {
			id := uuid.New()
			idCopy := id
			de := func(_ context.Context) *types.WorkspaceEdit { return nil }
			action, _ := snyk.NewDeferredCodeAction("Fix"+string(rune('A'+n%26)), &de, nil, "", nil)
			action.Uuid = &idCopy
			issues[i] = &snyk.Issue{CodeActions: []types.CodeAction{&action}}
		}
		return issues
	}

	ctrl := gomock.NewController(t)
	providerMock := mock_snyk.NewMockIssueProvider(ctrl)
	providerMock.EXPECT().
		IssuesForRange(gomock.Eq(path), gomock.Eq(converter.FromRange(r))).
		DoAndReturn(func(_ types.FilePath, _ types.Range) []types.Issue {
			return issueGen()
		}).
		AnyTimes()

	service := codeaction.NewService(
		engine,
		providerMock,
		watcher.NewFileWatcher(),
		notification.NewMockNotifier(),
		featureflag.NewFakeService(),
		types.NewConfigResolver(engine.GetLogger()),
		nil,
	)

	params := types.CodeActionParams{
		TextDocument: sglsp.TextDocumentIdentifier{URI: uriPath},
		Range:        r,
		Context:      types.CodeActionContext{},
	}

	// Serial pre-population: cache one batch so readers have entries to find.
	initialActions := service.GetCodeActions(params)
	require.NotEmpty(t, initialActions, "cache must be populated before the race test")

	ctx := context.Background()
	var wg sync.WaitGroup

	// Single writer goroutine: repeatedly calls GetCodeActions to drive cache writes.
	// Each call produces its own fresh issue list (via issueGen) so no CodeAction
	// pointer is shared between calls, keeping the only shared state as actionsCache.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 50 {
			service.GetCodeActions(params)
		}
	}()

	// Reader goroutines: each calls ResolveCodeAction on one pre-cached LSP action.
	// This exercises the concurrent map lookup+delete path.
	for _, a := range initialActions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 5 {
				// Entry may already be deleted on the first call; errors are expected.
				// We only care about the absence of a concurrent-map-access panic.
				_, _ = service.ResolveCodeAction(ctx, a)
			}
		}()
	}

	wg.Wait()
	// Reaching here under -race without a "concurrent map read/write" panic confirms
	// that all actionsCache accesses are properly serialized by actionsCacheMu.
}
