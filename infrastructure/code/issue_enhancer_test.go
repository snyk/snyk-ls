/*
 * © 2022-2024 Snyk Limited
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

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

func Test_getShardKey(t *testing.T) {
	const testToken = "TEST"
	t.Run("should return root path hash", func(t *testing.T) {
		// Case 1: rootPath exists
		sampleRootPath := "C:\\GIT\\root"
		// deepcode ignore HardcodedPassword/test: false positive
		token := testToken
		assert.Equal(t, util.Hash([]byte(sampleRootPath)), getShardKey(sampleRootPath, token))
	})

	t.Run("should return token hash", func(t *testing.T) {
		// Case 2: rootPath empty, token exists
		sampleRootPath := ""
		// deepcode ignore HardcodedPassword/test: false positive
		token := testToken
		assert.Equal(t, util.Hash([]byte(token)), getShardKey(sampleRootPath, token))
	})

	t.Run("should return empty shard key", func(t *testing.T) {
		// Case 3: No token, no rootPath set
		sampleRootPath := ""
		// deepcode ignore HardcodedPassword/test: false positive
		token := ""
		assert.Equal(t, "", getShardKey(sampleRootPath, token))
	})
}

func TestIssueEnhancer_autofixShowDetailsFunc(t *testing.T) {
	c := config.CurrentConfig()
	fakeSnykCode := FakeSnykCodeClient{C: c}
	issueEnhancer := IssueEnhancer{
		SnykCode:     &fakeSnykCode,
		instrumentor: NewCodeInstrumentor(),
		rootPath:     "/Users/user/workspace/blah",
		c:            c,
	}
	issue := snyk.Issue{
		AffectedFilePath: "/Users/user/workspace/blah/app.js",
		Product:          product.ProductCode,
		AdditionalData:   snyk.CodeIssueData{Key: "123"},
		Range:            fakeRange,
	}
	expectedURI := "snyk:///Users/user/workspace/blah/app.js?product=Snyk+Code&issueId=123&action=showInDetailPanel"

	t.Run("returns CommandData with correct URI and range", func(t *testing.T) {
		commandDataFunc := issueEnhancer.autofixShowDetailsFunc(context.Background(), issue)
		commandData := commandDataFunc()

		assert.Equal(t, types.NavigateToRangeCommand, commandData.Title)
		assert.Equal(t, types.NavigateToRangeCommand, commandData.CommandId)
		assert.Equal(t, expectedURI, commandData.Arguments[0])
		assert.Equal(t, issue.Range, commandData.Arguments[1])
	})
}

func Test_addIssueActions(t *testing.T) {
	c := config.CurrentConfig()
	fakeSnykCode := FakeSnykCodeClient{C: c}
	mockNotifier := notification.NewMockNotifier()
	issueEnhancer := IssueEnhancer{
		SnykCode:     &fakeSnykCode,
		notifier:     mockNotifier,
		instrumentor: NewCodeInstrumentor(),
		c:            c,
	}

	var setupCodeSettings = func() {
		resetCodeSettings()
		c.SetSnykCodeEnabled(true)
		c.SetSnykLearnCodeActionsEnabled(false)
		getCodeSettings().SetAutofixEnabled(true)
	}

	var setupFakeIssues = func(isIgnored bool, isAutofixable bool) []snyk.Issue {
		return []snyk.Issue{
			{
				ID:               "SNYK-123",
				Range:            fakeRange,
				Severity:         snyk.High,
				Product:          product.ProductCode,
				IssueType:        snyk.CodeQualityIssue,
				Message:          "This is a dummy error (severity error)",
				CodelensCommands: []types.CommandData{FakeCommand},
				CodeActions:      []snyk.CodeAction{FakeCodeAction},
				IsIgnored:        isIgnored,
				AdditionalData: snyk.CodeIssueData{
					Key:           uuid.New().String(),
					IsAutofixable: isAutofixable,
				},
			},
		}
	}

	t.Run("Includes AI fixes if issue is not ignored", func(t *testing.T) {
		setupCodeSettings()
		defer t.Cleanup(resetCodeSettings)
		fakeIssues := setupFakeIssues(false, true)

		issueEnhancer.addIssueActions(context.Background(), fakeIssues)

		issueData, ok := fakeIssues[0].AdditionalData.(snyk.CodeIssueData)
		require.True(t, ok)
		assert.True(t, issueData.HasAIFix)
		assert.Len(t, fakeIssues[0].CodelensCommands, 2)
		assert.Len(t, fakeIssues[0].CodeActions, 2)
	})

	t.Run("Does not include AI fixes if issue is not autofixable", func(t *testing.T) {
		setupCodeSettings()
		defer t.Cleanup(resetCodeSettings)
		fakeIssues := setupFakeIssues(false, false)

		issueEnhancer.addIssueActions(context.Background(), fakeIssues)

		issueData, ok := fakeIssues[0].AdditionalData.(snyk.CodeIssueData)
		require.True(t, ok)
		assert.False(t, issueData.HasAIFix)
		assert.Len(t, fakeIssues[0].CodelensCommands, 1)
		assert.Len(t, fakeIssues[0].CodeActions, 1)
	})

	t.Run("Does not include AI fixes even if it is autofixable if issue is ignored", func(t *testing.T) {
		setupCodeSettings()
		defer t.Cleanup(resetCodeSettings)
		fakeIssues := setupFakeIssues(true, true)

		issueEnhancer.addIssueActions(context.Background(), fakeIssues)

		issueData, ok := fakeIssues[0].AdditionalData.(snyk.CodeIssueData)
		require.True(t, ok)
		assert.True(t, issueData.HasAIFix)
		assert.Len(t, fakeIssues[0].CodelensCommands, 1)
		assert.Len(t, fakeIssues[0].CodeActions, 1)
	})
}

func Test_ideSnykURI(t *testing.T) {
	t.Run("generates correct URI", func(t *testing.T) {
		issue, ideAction, expectedURI := setupAiFixTestData()
		actualURI := SnykMagnetUri(issue, ideAction)
		assert.Equal(t, expectedURI, actualURI)
	})

	t.Run("handles missing Key in additional data", func(t *testing.T) {
		issue, ideAction, expectedURI := setupAiFixTestData()
		actualURI := SnykMagnetUri(issue, ideAction)
		assert.Equal(t, expectedURI, actualURI)
	})
}

func TestIssueId(t *testing.T) {
	testCases := []struct {
		name     string
		issue    snyk.Issue
		expected string
	}{
		{
			name: "Nil AdditionalData",
			issue: snyk.Issue{
				ID:             "vuln-id",
				AdditionalData: nil,
			},
			expected: "vuln-id",
		},
		{
			name: "CodeIssueData with empty key",
			issue: snyk.Issue{
				ID: "vuln-id",
				AdditionalData: snyk.CodeIssueData{
					Key: "",
				},
			},
			expected: "vuln-id",
		},
		{
			name: "CodeIssueData with key",
			issue: snyk.Issue{
				ID: "vuln-id",
				AdditionalData: snyk.CodeIssueData{
					Key: "code-issue-key",
				},
			},
			expected: "code-issue-key",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := issueId(tc.issue)
			if result != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, result)
			}
		})
	}
}

func setupAiFixTestData() (issue snyk.Issue, ideAction string, expectedURI string) {
	issue = snyk.Issue{
		AffectedFilePath: "/Users/user/workspace/blah/app.js",
		Product:          "Code",
		AdditionalData:   snyk.CodeIssueData{Key: "123"}, // Provide additional data
	}
	ideAction = "showInDetailPanel"
	expectedURI = "snyk:///Users/user/workspace/blah/app.js?product=Code&issueId=123&action=showInDetailPanel"

	return
}
