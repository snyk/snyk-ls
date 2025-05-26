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
	"runtime"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/mock_snyk"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

func Test_codeFixDiffs_Execute(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	server := mock_types.NewMockServer(ctrl)
	server.EXPECT().Callback(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
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
		notifier:      notification.NewMockNotifier(),
		codeScanner:   codeScanner,
		c:             c,
		srv:           server,
		snykApiClient: snykApiClient,
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

		suggestions, err := cut.Execute(context.Background())

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

		suggestions, err := cut.Execute(context.Background())

		require.Emptyf(t, suggestions, "suggestions should be empty")
		require.Error(t, err)
	})
}
