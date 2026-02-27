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

package secrets

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

const ufmResultContentType = "application/ufm.result"

// ufmTestResult mirrors the wire format expected by ufm.GetTestResultsFromWorkflowData
type ufmTestResult struct {
	ExecutionState   string                `json:"executionState"`
	FindingsComplete bool                  `json:"findingsComplete"`
	FindingsData     []testapi.FindingData `json:"findings,omitempty"`
}

func createUFMWorkflowData(t *testing.T, findings []testapi.FindingData) workflow.Data {
	t.Helper()
	results := []ufmTestResult{{
		ExecutionState:   "finished",
		FindingsComplete: true,
		FindingsData:     findings,
	}}
	payload, err := json.Marshal(results)
	require.NoError(t, err)

	workflowID := workflow.NewWorkflowIdentifier("secrets.test")
	return workflow.NewData(
		workflow.NewTypeIdentifier(workflowID, "TestResult"),
		ufmResultContentType,
		payload,
	)
}

func secretsEnabledFolderConfig(folderPath types.FilePath) *types.FolderConfig {
	return &types.FolderConfig{
		FolderPath:   folderPath,
		FeatureFlags: map[string]bool{featureflag.SnykSecretsEnabled: true},
	}
}

func TestScanner_Scan(t *testing.T) {
	t.Run("returns issues from findings", func(t *testing.T) {
		c := testutil.UnitTest(t)
		mockEngine, _ := testutil.SetUpEngineMock(t, c)

		loc := newSourceLocation("src/config.yml", 10, intPtr(5), intPtr(10), intPtr(20))
		cwe := newCweProblem("CWE-798")
		rule := newSecretsRuleProblem("hardcoded-secret", "Hardcoded Secret", []string{"Security"})
		finding := newFinding(
			"test-key", "Hardcoded Secret Found", "A hardcoded secret was detected",
			testapi.SeverityHigh, []testapi.FindingLocation{loc}, []testapi.Problem{cwe, rule}, nil,
		)

		data := createUFMWorkflowData(t, []testapi.FindingData{finding})
		workflowID := workflow.NewWorkflowIdentifier("secrets.test")
		mockEngine.EXPECT().InvokeWithConfig(workflowID, gomock.Any()).
			Return([]workflow.Data{data}, nil)

		workspaceFolder := types.FilePath(t.TempDir())
		scanner := New(c, performance.NewInstrumentor(), &snyk_api.FakeApiClient{}, featureflag.NewFakeService(), notification.NewMockNotifier(), nil)

		issues, err := scanner.Scan(t.Context(), workspaceFolder, secretsEnabledFolderConfig(workspaceFolder))

		require.NoError(t, err)
		require.Len(t, issues, 1)
		assert.Equal(t, "hardcoded-secret", issues[0].GetID())
		assert.Equal(t, types.High, issues[0].GetSeverity())
		assert.Equal(t, types.FilePath(filepath.Join(string(workspaceFolder), "src/config.yml")), issues[0].GetAffectedFilePath())
	})

	t.Run("returns multiple issues from multiple findings", func(t *testing.T) {
		c := testutil.UnitTest(t)
		mockEngine, _ := testutil.SetUpEngineMock(t, c)

		loc1 := newSourceLocation("a.yml", 1, nil, nil, nil)
		loc2 := newSourceLocation("b.yml", 5, nil, nil, nil)
		f1 := newFinding("key-1", "Secret 1", "desc1", testapi.SeverityHigh, []testapi.FindingLocation{loc1}, nil, nil)
		f2 := newFinding("key-2", "Secret 2", "desc2", testapi.SeverityMedium, []testapi.FindingLocation{loc2}, nil, nil)

		data := createUFMWorkflowData(t, []testapi.FindingData{f1, f2})
		workflowID := workflow.NewWorkflowIdentifier("secrets.test")
		mockEngine.EXPECT().InvokeWithConfig(workflowID, gomock.Any()).
			Return([]workflow.Data{data}, nil)

		workspaceFolder := types.FilePath(t.TempDir())
		scanner := New(c, performance.NewInstrumentor(), &snyk_api.FakeApiClient{}, featureflag.NewFakeService(), notification.NewMockNotifier(), nil)

		issues, err := scanner.Scan(t.Context(), workspaceFolder, secretsEnabledFolderConfig(workspaceFolder))

		require.NoError(t, err)
		require.Len(t, issues, 2)
		assert.Equal(t, "key-1", issues[0].GetID())
		assert.Equal(t, "key-2", issues[1].GetID())
	})

	t.Run("caches scan results", func(t *testing.T) {
		c := testutil.UnitTest(t)
		mockEngine, _ := testutil.SetUpEngineMock(t, c)

		loc := newSourceLocation("secret.yml", 1, nil, nil, nil)
		finding := newFinding("cache-key", "Cached Secret", "desc", testapi.SeverityHigh, []testapi.FindingLocation{loc}, nil, nil)

		data := createUFMWorkflowData(t, []testapi.FindingData{finding})
		workflowID := workflow.NewWorkflowIdentifier("secrets.test")
		mockEngine.EXPECT().InvokeWithConfig(workflowID, gomock.Any()).
			Return([]workflow.Data{data}, nil)

		workspaceFolder := types.FilePath(t.TempDir())
		scanner := New(c, performance.NewInstrumentor(), &snyk_api.FakeApiClient{}, featureflag.NewFakeService(), notification.NewMockNotifier(), nil)

		issues, err := scanner.Scan(t.Context(), workspaceFolder, secretsEnabledFolderConfig(workspaceFolder))

		require.NoError(t, err)
		require.Len(t, issues, 1)

		cachedIssues := scanner.Issues()
		totalCached := 0
		for _, fileIssues := range cachedIssues {
			totalCached += len(fileIssues)
		}
		assert.Equal(t, 1, totalCached)
	})

	t.Run("returns empty when no token", func(t *testing.T) {
		c := testutil.UnitTest(t)
		testutil.SetUpEngineMock(t, c)
		c.SetToken("")

		workspaceFolder := types.FilePath(t.TempDir())
		scanner := New(c, performance.NewInstrumentor(), &snyk_api.FakeApiClient{}, featureflag.NewFakeService(), notification.NewMockNotifier(), nil)

		issues, err := scanner.Scan(t.Context(), workspaceFolder, secretsEnabledFolderConfig(workspaceFolder))

		assert.NoError(t, err)
		assert.Empty(t, issues)
	})

	t.Run("returns error when feature flag disabled", func(t *testing.T) {
		c := testutil.UnitTest(t)
		testutil.SetUpEngineMock(t, c)

		workspaceFolder := types.FilePath(t.TempDir())
		folderConfig := &types.FolderConfig{
			FolderPath:   workspaceFolder,
			FeatureFlags: map[string]bool{featureflag.SnykSecretsEnabled: false},
		}
		scanner := New(c, performance.NewInstrumentor(), &snyk_api.FakeApiClient{}, featureflag.NewFakeService(), notification.NewMockNotifier(), nil)

		issues, err := scanner.Scan(t.Context(), workspaceFolder, folderConfig)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "feature flag")
		assert.Empty(t, issues)
	})

	t.Run("returns error when InvokeWithConfig fails", func(t *testing.T) {
		c := testutil.UnitTest(t)
		mockEngine, _ := testutil.SetUpEngineMock(t, c)

		workflowID := workflow.NewWorkflowIdentifier("secrets.test")
		mockEngine.EXPECT().InvokeWithConfig(workflowID, gomock.Any()).
			Return(nil, errors.New("engine invocation failed"))

		workspaceFolder := types.FilePath(t.TempDir())
		scanner := New(c, performance.NewInstrumentor(), &snyk_api.FakeApiClient{}, featureflag.NewFakeService(), notification.NewMockNotifier(), nil)

		issues, err := scanner.Scan(t.Context(), workspaceFolder, secretsEnabledFolderConfig(workspaceFolder))

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "engine invocation failed")
		assert.Nil(t, issues)
	})

	t.Run("returns empty when InvokeWithConfig returns empty data", func(t *testing.T) {
		c := testutil.UnitTest(t)
		mockEngine, _ := testutil.SetUpEngineMock(t, c)

		workflowID := workflow.NewWorkflowIdentifier("secrets.test")
		mockEngine.EXPECT().InvokeWithConfig(workflowID, gomock.Any()).
			Return([]workflow.Data{}, nil)

		workspaceFolder := types.FilePath(t.TempDir())
		scanner := New(c, performance.NewInstrumentor(), &snyk_api.FakeApiClient{}, featureflag.NewFakeService(), notification.NewMockNotifier(), nil)

		issues, err := scanner.Scan(t.Context(), workspaceFolder, secretsEnabledFolderConfig(workspaceFolder))

		assert.NoError(t, err)
		assert.Empty(t, issues)
	})

	t.Run("returns empty when result has nil payload", func(t *testing.T) {
		c := testutil.UnitTest(t)
		mockEngine, _ := testutil.SetUpEngineMock(t, c)

		workflowID := workflow.NewWorkflowIdentifier("secrets.test")
		data := workflow.NewData(
			workflow.NewTypeIdentifier(workflowID, "TestResult"),
			"application/json",
			nil,
		)
		mockEngine.EXPECT().InvokeWithConfig(workflowID, gomock.Any()).
			Return([]workflow.Data{data}, nil)

		workspaceFolder := types.FilePath(t.TempDir())
		scanner := New(c, performance.NewInstrumentor(), &snyk_api.FakeApiClient{}, featureflag.NewFakeService(), notification.NewMockNotifier(), nil)

		issues, err := scanner.Scan(t.Context(), workspaceFolder, secretsEnabledFolderConfig(workspaceFolder))

		assert.NoError(t, err)
		assert.Empty(t, issues)
	})

	t.Run("file paths are relative to workspace folder", func(t *testing.T) {
		c := testutil.UnitTest(t)
		mockEngine, _ := testutil.SetUpEngineMock(t, c)

		loc := newSourceLocation("config.yml", 1, nil, nil, nil)
		finding := newFinding("key", "title", "desc", testapi.SeverityLow, []testapi.FindingLocation{loc}, nil, nil)

		data := createUFMWorkflowData(t, []testapi.FindingData{finding})
		workflowID := workflow.NewWorkflowIdentifier("secrets.test")
		mockEngine.EXPECT().InvokeWithConfig(workflowID, gomock.Any()).
			Return([]workflow.Data{data}, nil)

		workspaceFolder := types.FilePath(t.TempDir())
		filePath := types.FilePath(filepath.Join(string(workspaceFolder), "subdir"))
		scanner := New(c, performance.NewInstrumentor(), &snyk_api.FakeApiClient{}, featureflag.NewFakeService(), notification.NewMockNotifier(), nil)

		issues, err := scanner.Scan(t.Context(), filePath, secretsEnabledFolderConfig(workspaceFolder))

		require.NoError(t, err)
		require.Len(t, issues, 1)
		assert.Equal(t, types.FilePath(filepath.Join(string(workspaceFolder), "config.yml")), issues[0].GetAffectedFilePath())
	})
}
