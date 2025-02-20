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
	"context"
	"github.com/creachadair/jrpc2"
	"github.com/snyk/code-client-go/llm"
	"runtime"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_codeFixDiffs_Command(t *testing.T) {

}

type mockIssueProvider struct {
}
type ServerImplMock struct{}

func (b *ServerImplMock) Callback(_ context.Context, _ string, _ any) (*jrpc2.Response, error) { // todo: check if better way exists, mocking? go mock / testify
	return nil, nil
}
func (b *ServerImplMock) Notify(_ context.Context, _ string, _ any) error {
	return nil
}

func (m mockIssueProvider) Issues() snyk.IssuesByFile {
	panic("this should not be called")
}

func (m mockIssueProvider) IssuesForFile(_ string) []snyk.Issue {
	panic("this should not be called")
}

func (m mockIssueProvider) IssuesForRange(_ string, _ snyk.Range) []snyk.Issue {
	panic("this should not be called")
}
func (m mockIssueProvider) Issue(key string) snyk.Issue {
	return snyk.Issue{ID: key}
}

func Test_codeFixDiffs_Execute(t *testing.T) {
	c := testutil.UnitTest(t)
	instrumentor := code.NewCodeInstrumentor()
	snykCodeClient := &code.FakeSnykCodeClient{
		UnifiedDiffSuggestions: []code.AutofixUnifiedDiffSuggestion{
			{
				FixId:               uuid.NewString(),
				UnifiedDiffsPerFile: nil,
			},
		},
	}
	snykApiClient := &snyk_api.FakeApiClient{CodeEnabled: true}
	codeScanner := &code.Scanner{
		BundleUploader: code.NewBundler(c, snykCodeClient, instrumentor),
		SnykApiClient:  snykApiClient,
		C:              c,
	}
	cut := codeFixDiffs{
		notifier:           notification.NewMockNotifier(),
		codeScanner:        codeScanner,
		c:                  c,
		srv:                &ServerImplMock{},
		deepCodeLLMBinding: llm.NewDeepcodeLLMBinding(),
	}
	if runtime.GOOS == "windows" {
		codeScanner.AddBundleHash("\\folderPath", "bundleHash")
	} else {
		codeScanner.AddBundleHash("/folderPath", "bundleHash")
	}
	t.Run("happy path", func(t *testing.T) {
		cut.issueProvider = mockIssueProvider{}

		cut.command = types.CommandData{
			Arguments: []any{"file:///folderPath", "file:///folderPath/issuePath", "issueId"},
		}

		suggestions, err := cut.Execute(context.Background())

		// Code fix diffs command doesn't return suggestions anymore
		// TODO: handle getting the suggestions
		require.Emptyf(t, suggestions, "suggestions should not be empty")
		require.NoError(t, err)
	})

	t.Run("unhappy - file not beneath folder", func(t *testing.T) {
		cut.issueProvider = mockIssueProvider{}
		cut.command = types.CommandData{
			Arguments: []any{"file:///folderPath", "file:///anotherFolder/issuePath", "issueId"},
		}

		suggestions, err := cut.Execute(context.Background())

		require.Emptyf(t, suggestions, "suggestions should be empty")
		require.Error(t, err)
	})

	t.Run("unhappy - folder empty", func(t *testing.T) {
		cut.issueProvider = mockIssueProvider{}
		cut.command = types.CommandData{
			Arguments: []any{"", "file:///anotherFolder/issuePath", "issueId"},
		}

		suggestions, err := cut.Execute(context.Background())

		require.Emptyf(t, suggestions, "suggestions should be empty")
		require.Error(t, err)
	})

	t.Run("unhappy - file empty", func(t *testing.T) {
		cut.issueProvider = mockIssueProvider{}
		cut.command = types.CommandData{
			Arguments: []any{"file://folder", "", "issueId"},
		}

		suggestions, err := cut.Execute(context.Background())

		require.Emptyf(t, suggestions, "suggestions should be empty")
		require.Error(t, err)
	})
}
