/*
 * © 2023 Snyk Limited
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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/code-client-go/llm"

	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/testutil/workspace"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_codeFixFeedback_SubmittedSuccessfully(t *testing.T) {
	codeFixFeedbackCmd := codeFixFeedback{
		command: types.CommandData{
			Arguments: []any{"fixId", code.FixPositiveFeedback},
		},
	}

	_, err := codeFixFeedbackCmd.Execute(t.Context())

	assert.NoError(t, err)
}

func Test_getFolderFromFixId_ReturnsErrorWhenNoRenderer(t *testing.T) {
	c := testutil.UnitTest(t)

	// Reset singleton to ensure it's not initialized from previous tests
	code.ResetHTMLRenderer()

	cmd := &codeFixFeedback{}
	result, err := cmd.getFolderFromFixId(c, "test-fix-id")

	// Should return error when renderer not initialized
	assert.ErrorContains(t, err, "HTML renderer not initialized")
	assert.Equal(t, types.FilePath(""), result)
}

func Test_getFolderFromFixId_ReturnsErrorWhenNoWorkspace(t *testing.T) {
	c := testutil.UnitTest(t)

	// Initialize HtmlRenderer but don't set up workspace
	fakeFFService := featureflag.NewFakeService()
	_, err := code.GetHTMLRenderer(c, fakeFFService)
	require.NoError(t, err)

	cmd := &codeFixFeedback{}
	result, err := cmd.getFolderFromFixId(c, "test-fix-id")

	// Should return error when no workspace configured
	assert.Error(t, err)
	assert.Equal(t, types.FilePath(""), result)
}

func Test_getFolderFromFixId_ReturnsErrorWhenFixIdNotFound(t *testing.T) {
	c := testutil.UnitTest(t)

	// Setup workspace with folders
	workspaceutil.SetupWorkspace(t, c, types.FilePath("/workspace/folder1"), types.FilePath("/workspace/folder2"))

	// Initialize HtmlRenderer
	fakeFFService := featureflag.NewFakeService()
	_, err := code.GetHTMLRenderer(c, fakeFFService)
	require.NoError(t, err)

	cmd := &codeFixFeedback{}
	result, err := cmd.getFolderFromFixId(c, "non-existent-fix-id")

	// Should return error when fixId doesn't exist in fix results
	assert.ErrorContains(t, err, "fix results not found")
	assert.Equal(t, types.FilePath(""), result)
}

func Test_getFolderFromFixId_ReturnsCorrectFolder(t *testing.T) {
	c := testutil.UnitTest(t)

	// Setup workspace with folders
	workspaceutil.SetupWorkspace(t, c, types.FilePath("/workspace/folder1"), types.FilePath("/workspace/folder2"))

	// Initialize HtmlRenderer
	fakeFFService := featureflag.NewFakeService()
	renderer, err := code.GetHTMLRenderer(c, fakeFFService)
	require.NoError(t, err)

	// Populate AiFixHandler with test fix results
	testFixId := "test-fix-123"
	testFilePath := "/workspace/folder2/src/vulnerable.go"
	testSuggestions := []llm.AutofixUnifiedDiffSuggestion{
		{
			FixId: testFixId,
			UnifiedDiffsPerFile: map[string]string{
				testFilePath: "--- a/src/vulnerable.go\n+++ b/src/vulnerable.go\n@@ -1,1 +1,1 @@\n-vulnerable code\n+fixed code\n",
			},
		},
	}
	renderer.AiFixHandler.SetAiFixDiffState(code.AiFixSuccess, testSuggestions, nil, nil)

	cmd := &codeFixFeedback{}
	result, err := cmd.getFolderFromFixId(c, testFixId)

	// Should correctly determine folder from fix results
	require.NoError(t, err)
	assert.Equal(t, types.FilePath("/workspace/folder2"), result)
}

func Test_getFolderFromFixId_ReturnsErrorWhenFileNotInAnyFolder(t *testing.T) {
	c := testutil.UnitTest(t)

	// Setup workspace with folders
	workspaceutil.SetupWorkspace(t, c, types.FilePath("/workspace/folder1"), types.FilePath("/workspace/folder2"))

	// Initialize HtmlRenderer
	fakeFFService := featureflag.NewFakeService()
	renderer, err := code.GetHTMLRenderer(c, fakeFFService)
	require.NoError(t, err)

	// Populate AiFixHandler with fix results for file outside workspace
	testFixId := "test-fix-outside"
	testFilePath := "/different/path/file.go"
	testSuggestions := []llm.AutofixUnifiedDiffSuggestion{
		{
			FixId: testFixId,
			UnifiedDiffsPerFile: map[string]string{
				testFilePath: "--- a/file.go\n+++ b/file.go\n@@ -1,1 +1,1 @@\n-old\n+new\n",
			},
		},
	}
	renderer.AiFixHandler.SetAiFixDiffState(code.AiFixSuccess, testSuggestions, nil, nil)

	cmd := &codeFixFeedback{}
	result, err := cmd.getFolderFromFixId(c, testFixId)

	// Should return error when file is not in any workspace folder
	assert.ErrorContains(t, err, "not in any workspace folder")
	assert.Equal(t, types.FilePath(""), result)
}

func Test_getFolderFromFixId_HandlesMultipleFolders(t *testing.T) {
	c := testutil.UnitTest(t)

	// Setup workspace with multiple folders
	workspaceutil.SetupWorkspace(t, c, types.FilePath("/workspace/project1"), types.FilePath("/workspace/project2"), types.FilePath("/workspace/project3"))

	// Initialize HtmlRenderer
	fakeFFService := featureflag.NewFakeService()
	renderer, err := code.GetHTMLRenderer(c, fakeFFService)
	require.NoError(t, err)

	// Test fix in first folder
	testFixId1 := "fix-in-project1"
	testFilePath1 := "/workspace/project1/main.go"
	testSuggestions1 := []llm.AutofixUnifiedDiffSuggestion{
		{
			FixId: testFixId1,
			UnifiedDiffsPerFile: map[string]string{
				testFilePath1: "diff content",
			},
		},
	}
	renderer.AiFixHandler.SetAiFixDiffState(code.AiFixSuccess, testSuggestions1, nil, nil)

	cmd := &codeFixFeedback{}
	result1, err := cmd.getFolderFromFixId(c, testFixId1)
	require.NoError(t, err)
	assert.Equal(t, types.FilePath("/workspace/project1"), result1)

	// Test fix in third folder
	testFixId3 := "fix-in-project3"
	testFilePath3 := "/workspace/project3/utils/helper.go"
	testSuggestions3 := []llm.AutofixUnifiedDiffSuggestion{
		{
			FixId: testFixId3,
			UnifiedDiffsPerFile: map[string]string{
				testFilePath3: "diff content",
			},
		},
	}
	renderer.AiFixHandler.SetAiFixDiffState(code.AiFixSuccess, testSuggestions3, nil, nil)

	result3, err := cmd.getFolderFromFixId(c, testFixId3)
	require.NoError(t, err)
	assert.Equal(t, types.FilePath("/workspace/project3"), result3)
}
