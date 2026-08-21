/*
 * © 2024 Snyk Limited
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

package command

import (
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/snyk/code-client-go/llm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/mock_snyk"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

func Test_codeFixDiffs_Execute(t *testing.T) {
	engine := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	server := mock_types.NewMockServer(ctrl)
	server.EXPECT().Callback(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	instrumentor := performance.NewInstrumentor()
	snykApiClient := &snyk_api.FakeApiClient{CodeEnabled: true}
	codeErrorReporter := code.NewCodeErrorReporter(error_reporting.NewTestErrorReporter(engine))
	codeScanner := code.New(engine, instrumentor, snykApiClient, codeErrorReporter, nil, featureflag.NewFakeService(), notification.NewNotifier(), code.NewCodeInstrumentor(), codeErrorReporter, code.NewFakeCodeScannerClient, testutil.DefaultConfigResolver(engine), testutil.NewDrainedProgressTracker())
	cut := codeFixDiffs{
		notifier:           notification.NewMockNotifier(),
		codeScanner:        codeScanner,
		engine:             engine,
		srv:                server,
		featureFlagService: featureflag.NewFakeService(),
	}
	if runtime.GOOS == "windows" {
		codeScanner.AddBundleHash("\\folderPath", "bundleHash")
	} else {
		codeScanner.AddBundleHash("/folderPath", "bundleHash")
	}
	t.Run("happy path", func(t *testing.T) {
		issueProvider := mock_snyk.NewMockIssueProvider(ctrl)
		issue := snyk.Issue{
			ID: uuid.NewString(),
		}
		issueProvider.EXPECT().Issue(gomock.Any()).Return(&issue)
		cut.issueProvider = issueProvider
		cut.command = types.CommandData{
			Arguments: []any{issue.ID},
		}

		suggestions, err := cut.Execute(t.Context())

		// Code fix diffs command doesn't return suggestions anymore
		// TODO: handle getting the suggestions
		require.Emptyf(t, suggestions, "suggestions should not be empty")
		require.NoError(t, err)
	})

	t.Run("unhappy - no args", func(t *testing.T) {
		cut.issueProvider = mock_snyk.NewMockIssueProvider(ctrl)
		cut.command = types.CommandData{
			Arguments: []any{},
		}

		suggestions, err := cut.Execute(t.Context())

		require.Emptyf(t, suggestions, "suggestions should be empty")
		require.Error(t, err)
	})
}

// Test_codeFixDiffs_Execute_SendsAiFixNotification proves that triggering a fix diff via the
// real production entrypoint (Execute -> handleResponse -> the real AiFixHandler state machine)
// results in a $/snyk.aiFix notification being sent on the real Notifier, with a payload that
// reflects the real AiFixHandler state. GetAutofixDiffs is driven to its deterministic,
// network-free error branch (no bundle hash registered for the issue's content root).
func Test_codeFixDiffs_Execute_SendsAiFixNotification(t *testing.T) {
	engine := testutil.UnitTest(t)
	t.Cleanup(code.ResetHTMLRenderer)
	ctrl := gomock.NewController(t)
	server := mock_types.NewMockServer(ctrl)
	server.EXPECT().Callback(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	instrumentor := performance.NewInstrumentor()
	snykApiClient := &snyk_api.FakeApiClient{CodeEnabled: true}
	codeErrorReporter := code.NewCodeErrorReporter(error_reporting.NewTestErrorReporter(engine))
	codeScanner := code.New(engine, instrumentor, snykApiClient, codeErrorReporter, nil, featureflag.NewFakeService(), notification.NewNotifier(), code.NewCodeInstrumentor(), codeErrorReporter, code.NewFakeCodeScannerClient, testutil.DefaultConfigResolver(engine))

	realNotifier := notification.NewNotifier()
	var mu sync.Mutex
	var received []types.AiFixNotification
	realNotifier.CreateListener(func(params any) {
		aiFix, ok := params.(types.AiFixNotification)
		if !ok {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		received = append(received, aiFix)
	})
	t.Cleanup(realNotifier.DisposeListener)

	issueProvider := mock_snyk.NewMockIssueProvider(ctrl)
	issue := snyk.Issue{ID: uuid.NewString()}
	issueProvider.EXPECT().Issue(gomock.Any()).Return(&issue)

	cut := codeFixDiffs{
		notifier:           realNotifier,
		codeScanner:        codeScanner,
		engine:             engine,
		srv:                server,
		featureFlagService: featureflag.NewFakeService(),
		issueProvider:      issueProvider,
		command:            types.CommandData{Arguments: []any{issue.ID}},
	}

	_, err := cut.Execute(t.Context())
	require.NoError(t, err)

	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, n := range received {
			if n.IssueId == issue.ID && n.Status == string(code.AiFixError) {
				return len(n.Fixes) == 0
			}
		}
		return false
	}, 2*time.Second, time.Millisecond, "expected a $/snyk.aiFix ERROR notification for issue %s", issue.ID)
}

func Test_aiFixResultsFrom(t *testing.T) {
	t.Run("no suggestions yields no fixes", func(t *testing.T) {
		assert.Empty(t, aiFixResultsFrom(nil))
	})

	t.Run("single suggestion with a single file", func(t *testing.T) {
		suggestions := []llm.AutofixUnifiedDiffSuggestion{
			{FixId: "fix-1", UnifiedDiffsPerFile: map[string]string{"main.go": "diff"}},
		}

		assert.Equal(t, []types.AiFixResult{{FixId: "fix-1", FilePath: "main.go"}}, aiFixResultsFrom(suggestions))
	})

	t.Run("multiple suggestions, one spanning multiple files, sorted deterministically", func(t *testing.T) {
		suggestions := []llm.AutofixUnifiedDiffSuggestion{
			{FixId: "fix-1", UnifiedDiffsPerFile: map[string]string{"b.go": "diff-b", "a.go": "diff-a"}},
			{FixId: "fix-2", UnifiedDiffsPerFile: map[string]string{"c.go": "diff-c"}},
		}

		assert.Equal(t, []types.AiFixResult{
			{FixId: "fix-1", FilePath: "a.go"},
			{FixId: "fix-1", FilePath: "b.go"},
			{FixId: "fix-2", FilePath: "c.go"},
		}, aiFixResultsFrom(suggestions))
	})
}
