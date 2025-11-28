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

package code

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow/sast_contract"

	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/learn/mock_learn"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/testutil/workspaceutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// Test_Scan_SetsContentRootCorrectly is an INTEGRATION TEST that verifies
// ContentRoot is set correctly on issues returned from scanning files in different folders.
func Test_Scan_SetsContentRootCorrectly(t *testing.T) {
	c := testutil.IntegTest(t)
	c.SetSnykCodeEnabled(true)
	// Set a fake token so Scan() passes the authentication check
	// We're using FakeCodeScannerClient, so we don't need a real token
	c.SetToken("00000000-0000-0000-0000-000000000001")

	// Set up two folders with different orgs
	folderPath1, folderPath2, _, folderOrg1, folderOrg2 := testutil.SetupFoldersWithOrgs(t, c)

	// Set up workspace with the folders
	// This is required for FolderOrganization to work
	_, _ = workspaceutil.SetupWorkspace(t, c, folderPath1, folderPath2)

	// Set up feature flag service with SAST settings
	fakeFeatureFlagService := featureflag.NewFakeService()
	fakeFeatureFlagService.SastSettings = &sast_contract.SastResponse{SastEnabled: true}

	// Create scanner with FakeCodeScannerClient to avoid real API calls
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	learnMock := mock_learn.NewMockService(ctrl)
	// Set up learn service mock to return empty lessons (needed by issue enhancer)
	learnMock.EXPECT().
		GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&learn.Lesson{}, nil).AnyTimes()

	scanner := New(
		c,
		performance.NewInstrumentor(),
		&snyk_api.FakeApiClient{CodeEnabled: true},
		newTestCodeErrorReporter(),
		learnMock,
		fakeFeatureFlagService,
		notification.NewNotifier(),
		NewCodeInstrumentor(),
		newTestCodeErrorReporter(),
		NewFakeCodeScannerClient,
	)

	// Create folder configs with SAST enabled
	folderConfig1 := &types.FolderConfig{
		FolderPath: folderPath1,
		SastSettings: &sast_contract.SastResponse{
			SastEnabled: true,
		},
	}

	folderConfig2 := &types.FolderConfig{
		FolderPath: folderPath2,
		SastSettings: &sast_contract.SastResponse{
			SastEnabled: true,
		},
	}

	// Test folder 1
	t.Run("folder 1", func(t *testing.T) {
		// Scan a file in folder 1
		// The FakeCodeScannerClient will return SARIF that gets converted to issues
		issues, err := scanner.Scan(context.Background(), types.FilePath("test1.js"), folderPath1, folderConfig1)
		require.NoError(t, err, "Scan should succeed for folder 1")
		require.NotEmpty(t, issues, "Should return issues from scan")

		// Verify all issues have ContentRoot set to folderPath1
		for _, issue := range issues {
			assert.Equal(t, folderPath1, issue.GetContentRoot(), "Issue ContentRoot should be set to folder 1")
			// Verify FolderOrganization returns the correct org for this issue's ContentRoot
			issueOrg := c.FolderOrganization(issue.GetContentRoot())
			assert.Equal(t, folderOrg1, issueOrg, "FolderOrganization should return folder 1's org for issue's ContentRoot")
		}
	})

	// Test folder 2
	t.Run("folder 2", func(t *testing.T) {
		// Scan a file in folder 2
		issues, err := scanner.Scan(context.Background(), types.FilePath("test2.js"), folderPath2, folderConfig2)
		require.NoError(t, err, "Scan should succeed for folder 2")
		require.NotEmpty(t, issues, "Should return issues from scan")

		// Verify all issues have ContentRoot set to folderPath2
		for _, issue := range issues {
			assert.Equal(t, folderPath2, issue.GetContentRoot(), "Issue ContentRoot should be set to folder 2")
			// Verify FolderOrganization returns the correct org for this issue's ContentRoot
			issueOrg := c.FolderOrganization(issue.GetContentRoot())
			assert.Equal(t, folderOrg2, issueOrg, "FolderOrganization should return folder 2's org for issue's ContentRoot")
		}
	})

	// Verify the orgs are different
	assert.NotEqual(t, folderOrg1, folderOrg2, "Folder orgs should be different")
}
