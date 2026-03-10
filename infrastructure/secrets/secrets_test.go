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
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
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
	prefixKeyConf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	fs := pflag.NewFlagSet("secrets-test", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	_ = prefixKeyConf.AddFlagSet(fs)
	fm := workflow.NewFlagMetadata(workflow.ConfigurationOptionsFromFlagset(fs))
	logger := zerolog.Nop()
	resolver := types.NewConfigResolver(&logger)
	resolver.SetPrefixKeyResolver(configresolver.New(prefixKeyConf, fm), prefixKeyConf, fm)
	fc := &types.FolderConfig{
		FolderPath:     folderPath,
		ConfigResolver: resolver,
	}
	fc.SetFeatureFlag(featureflag.SnykSecretsEnabled, true)
	return fc
}

func defaultResolver(engine workflow.Engine) types.ConfigResolverInterface {
	return testutil.DefaultConfigResolver(engine)
}

// TestScanner_Scan_UsesConfigResolverFromContext FC-068: Secrets scanner uses resolver from context when available
func TestScanner_Scan_UsesConfigResolverFromContext(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	engine := testutil.UnitTest(t)
	mockResolver := mock_types.NewMockConfigResolverInterface(ctrl)
	mockResolver.EXPECT().
		IsProductEnabledForFolder(product.ProductSecrets, gomock.Any()).
		Return(false).
		Times(1)

	workspaceFolder := types.FilePath(t.TempDir())
	scanner := New(engine.GetConfiguration(), engine, engine.GetLogger(), performance.NewInstrumentor(), &snyk_api.FakeApiClient{}, featureflag.NewFakeService(), notification.NewMockNotifier(), defaultResolver(engine))
	ctx := ctx2.NewContextWithConfigResolver(context.Background(), mockResolver)
	ctx = ctx2.NewContextWithFolderConfig(ctx, secretsEnabledFolderConfig(workspaceFolder))

	issues, err := scanner.Scan(ctx, workspaceFolder)

	assert.NoError(t, err)
	assert.Empty(t, issues)
}

// TestScanner_Scan_FallsBackToStructFieldWhenNoResolverInContext FC-064: Secrets scanner falls back to struct field when context has no resolver
func TestScanner_Scan_FallsBackToStructFieldWhenNoResolverInContext(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	engine := testutil.UnitTest(t)
	mockResolver := mock_types.NewMockConfigResolverInterface(ctrl)
	mockResolver.EXPECT().
		IsProductEnabledForFolder(product.ProductSecrets, gomock.Any()).
		Return(false).
		Times(1)

	workspaceFolder := types.FilePath(t.TempDir())
	scanner := New(engine.GetConfiguration(), engine, engine.GetLogger(), performance.NewInstrumentor(), &snyk_api.FakeApiClient{}, featureflag.NewFakeService(), notification.NewMockNotifier(), mockResolver)
	ctx := ctx2.NewContextWithFolderConfig(context.Background(), secretsEnabledFolderConfig(workspaceFolder))

	issues, err := scanner.Scan(ctx, workspaceFolder)

	assert.NoError(t, err)
	assert.Empty(t, issues)
}

func TestScanner_Scan(t *testing.T) {
	t.Run("returns issues from findings", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		mockEngine, mockConf := testutil.SetUpEngineMock(t, engine)
		mockConf.Set(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled), true)

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
		scanner := New(mockConf, mockEngine, engine.GetLogger(), performance.NewInstrumentor(), &snyk_api.FakeApiClient{}, featureflag.NewFakeService(), notification.NewMockNotifier(), defaultResolver(mockEngine))
		ctx := ctx2.NewContextWithFolderConfig(t.Context(), secretsEnabledFolderConfig(workspaceFolder))

		issues, err := scanner.Scan(ctx, workspaceFolder)

		require.NoError(t, err)
		require.Len(t, issues, 1)
		assert.Equal(t, "hardcoded-secret", issues[0].GetID())
		assert.Equal(t, types.High, issues[0].GetSeverity())
		assert.Equal(t, types.FilePath(filepath.Join(string(workspaceFolder), "src/config.yml")), issues[0].GetAffectedFilePath())
	})

	t.Run("returns multiple issues from multiple findings", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		mockEngine, mockConf := testutil.SetUpEngineMock(t, engine)
		mockConf.Set(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled), true)

		loc1 := newSourceLocation("a.yml", 1, nil, nil, nil)
		loc2 := newSourceLocation("b.yml", 5, nil, nil, nil)
		f1 := newFinding("key-1", "Secret 1", "desc1", testapi.SeverityHigh, []testapi.FindingLocation{loc1}, nil, nil)
		f2 := newFinding("key-2", "Secret 2", "desc2", testapi.SeverityMedium, []testapi.FindingLocation{loc2}, nil, nil)

		data := createUFMWorkflowData(t, []testapi.FindingData{f1, f2})
		workflowID := workflow.NewWorkflowIdentifier("secrets.test")
		mockEngine.EXPECT().InvokeWithConfig(workflowID, gomock.Any()).
			Return([]workflow.Data{data}, nil)

		workspaceFolder := types.FilePath(t.TempDir())
		scanner := New(mockConf, mockEngine, engine.GetLogger(), performance.NewInstrumentor(), &snyk_api.FakeApiClient{}, featureflag.NewFakeService(), notification.NewMockNotifier(), defaultResolver(mockEngine))
		ctx := ctx2.NewContextWithFolderConfig(t.Context(), secretsEnabledFolderConfig(workspaceFolder))

		issues, err := scanner.Scan(ctx, workspaceFolder)

		require.NoError(t, err)
		require.Len(t, issues, 2)
		assert.Equal(t, "key-1", issues[0].GetID())
		assert.Equal(t, "key-2", issues[1].GetID())
	})

	t.Run("caches scan results", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		mockEngine, mockConf := testutil.SetUpEngineMock(t, engine)
		mockConf.Set(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled), true)

		loc := newSourceLocation("secret.yml", 1, nil, nil, nil)
		finding := newFinding("cache-key", "Cached Secret", "desc", testapi.SeverityHigh, []testapi.FindingLocation{loc}, nil, nil)

		data := createUFMWorkflowData(t, []testapi.FindingData{finding})
		workflowID := workflow.NewWorkflowIdentifier("secrets.test")
		mockEngine.EXPECT().InvokeWithConfig(workflowID, gomock.Any()).
			Return([]workflow.Data{data}, nil)

		workspaceFolder := types.FilePath(t.TempDir())
		scanner := New(mockConf, mockEngine, engine.GetLogger(), performance.NewInstrumentor(), &snyk_api.FakeApiClient{}, featureflag.NewFakeService(), notification.NewMockNotifier(), defaultResolver(mockEngine))
		ctx := ctx2.NewContextWithFolderConfig(t.Context(), secretsEnabledFolderConfig(workspaceFolder))

		issues, err := scanner.Scan(ctx, workspaceFolder)

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
		engine, tokenService := testutil.UnitTestWithEngine(t)
		mockEngine, mockConf := testutil.SetUpEngineMock(t, engine)
		mockConf.Set(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled), true)
		tokenService.SetToken(mockConf, "")

		workspaceFolder := types.FilePath(t.TempDir())
		scanner := New(mockConf, mockEngine, engine.GetLogger(), performance.NewInstrumentor(), &snyk_api.FakeApiClient{}, featureflag.NewFakeService(), notification.NewMockNotifier(), defaultResolver(mockEngine))
		ctx := ctx2.NewContextWithFolderConfig(t.Context(), secretsEnabledFolderConfig(workspaceFolder))

		issues, err := scanner.Scan(ctx, workspaceFolder)

		assert.NoError(t, err)
		assert.Empty(t, issues)
	})

	t.Run("returns error when feature flag disabled", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		mockEngine, mockConf := testutil.SetUpEngineMock(t, engine)
		mockConf.Set(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled), true)

		workspaceFolder := types.FilePath(t.TempDir())
		folderConfig := &types.FolderConfig{
			FolderPath:     workspaceFolder,
			ConfigResolver: testutil.DefaultConfigResolver(mockEngine),
		}
		folderConfig.SetFeatureFlag(featureflag.SnykSecretsEnabled, false)
		scanner := New(mockConf, mockEngine, engine.GetLogger(), performance.NewInstrumentor(), &snyk_api.FakeApiClient{}, featureflag.NewFakeService(), notification.NewMockNotifier(), defaultResolver(mockEngine))
		ctx := ctx2.NewContextWithFolderConfig(t.Context(), folderConfig)

		issues, err := scanner.Scan(ctx, workspaceFolder)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "feature flag")
		assert.Empty(t, issues)
	})

	t.Run("returns error when InvokeWithConfig fails", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		mockEngine, mockConf := testutil.SetUpEngineMock(t, engine)
		mockConf.Set(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled), true)

		workflowID := workflow.NewWorkflowIdentifier("secrets.test")
		mockEngine.EXPECT().InvokeWithConfig(workflowID, gomock.Any()).
			Return(nil, errors.New("engine invocation failed"))

		workspaceFolder := types.FilePath(t.TempDir())
		scanner := New(mockConf, mockEngine, engine.GetLogger(), performance.NewInstrumentor(), &snyk_api.FakeApiClient{}, featureflag.NewFakeService(), notification.NewMockNotifier(), defaultResolver(mockEngine))
		ctx := ctx2.NewContextWithFolderConfig(t.Context(), secretsEnabledFolderConfig(workspaceFolder))

		issues, err := scanner.Scan(ctx, workspaceFolder)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "engine invocation failed")
		assert.Nil(t, issues)
	})

	t.Run("returns empty when InvokeWithConfig returns empty data", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		mockEngine, mockConf := testutil.SetUpEngineMock(t, engine)
		mockConf.Set(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled), true)

		workflowID := workflow.NewWorkflowIdentifier("secrets.test")
		mockEngine.EXPECT().InvokeWithConfig(workflowID, gomock.Any()).
			Return([]workflow.Data{}, nil)

		workspaceFolder := types.FilePath(t.TempDir())
		scanner := New(mockConf, mockEngine, engine.GetLogger(), performance.NewInstrumentor(), &snyk_api.FakeApiClient{}, featureflag.NewFakeService(), notification.NewMockNotifier(), defaultResolver(mockEngine))
		ctx := ctx2.NewContextWithFolderConfig(t.Context(), secretsEnabledFolderConfig(workspaceFolder))

		issues, err := scanner.Scan(ctx, workspaceFolder)

		assert.NoError(t, err)
		assert.Empty(t, issues)
	})

	t.Run("returns empty when result has nil payload", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		mockEngine, mockConf := testutil.SetUpEngineMock(t, engine)
		mockConf.Set(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled), true)

		workflowID := workflow.NewWorkflowIdentifier("secrets.test")
		data := workflow.NewData(
			workflow.NewTypeIdentifier(workflowID, "TestResult"),
			"application/json",
			nil,
		)
		mockEngine.EXPECT().InvokeWithConfig(workflowID, gomock.Any()).
			Return([]workflow.Data{data}, nil)

		workspaceFolder := types.FilePath(t.TempDir())
		scanner := New(mockConf, mockEngine, engine.GetLogger(), performance.NewInstrumentor(), &snyk_api.FakeApiClient{}, featureflag.NewFakeService(), notification.NewMockNotifier(), defaultResolver(mockEngine))
		ctx := ctx2.NewContextWithFolderConfig(t.Context(), secretsEnabledFolderConfig(workspaceFolder))

		issues, err := scanner.Scan(ctx, workspaceFolder)

		assert.NoError(t, err)
		assert.Empty(t, issues)
	})

	t.Run("file paths are relative to workspace folder", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		mockEngine, mockConf := testutil.SetUpEngineMock(t, engine)
		mockConf.Set(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled), true)

		loc := newSourceLocation("config.yml", 1, nil, nil, nil)
		finding := newFinding("key", "title", "desc", testapi.SeverityLow, []testapi.FindingLocation{loc}, nil, nil)

		data := createUFMWorkflowData(t, []testapi.FindingData{finding})
		workflowID := workflow.NewWorkflowIdentifier("secrets.test")
		mockEngine.EXPECT().InvokeWithConfig(workflowID, gomock.Any()).
			Return([]workflow.Data{data}, nil)

		workspaceFolder := types.FilePath(t.TempDir())
		filePath := types.FilePath(filepath.Join(string(workspaceFolder), "subdir"))
		scanner := New(mockConf, mockEngine, engine.GetLogger(), performance.NewInstrumentor(), &snyk_api.FakeApiClient{}, featureflag.NewFakeService(), notification.NewMockNotifier(), defaultResolver(mockEngine))
		ctx := ctx2.NewContextWithFolderConfig(t.Context(), secretsEnabledFolderConfig(workspaceFolder))

		issues, err := scanner.Scan(ctx, filePath)

		require.NoError(t, err)
		require.Len(t, issues, 1)
		assert.Equal(t, types.FilePath(filepath.Join(string(workspaceFolder), "config.yml")), issues[0].GetAffectedFilePath())
	})
}
