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

package scanner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence/mock_persistence"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

func TestScanBaseBranch_AllProducts_ReceiveCorrectPathAndFolderPath(t *testing.T) {
	// All scanners now receive baseFolderPath as pathToScan.
	// The Code scanner determines it's a full workspace scan because pathToScan == workspaceFolderConfig.FolderPath.
	testCases := []struct {
		name    string
		product product.Product
	}{
		{name: "Code scanner receives baseFolderPath as pathToScan", product: product.ProductCode},
		{name: "OSS scanner receives baseFolderPath as pathToScan", product: product.ProductOpenSource},
		{name: "IaC scanner receives baseFolderPath as pathToScan", product: product.ProductInfrastructureAsCode},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			engine, tokenService := testutil.UnitTestWithEngine(t)
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Setup - use real temp dirs for path validation
			workspacePath := types.FilePath(t.TempDir())
			baseFolderPath := types.FilePath(t.TempDir())
			expectedOrg := "test-org"

			folderConfig := &types.FolderConfig{FolderPath: workspacePath}
			syncFolderToConfig(t, engine, folderConfig, &syncFolderOpts{
				ReferenceFolderPath: baseFolderPath,
				PreferredOrg:        expectedOrg,
				OrgSetByUser:        true,
			})

			// Create mock scanner with expectations
			mockScanner := mock_types.NewMockProductScanner(ctrl)
			mockScanner.EXPECT().Product().Return(tc.product).AnyTimes()
			mockScanner.EXPECT().IsEnabledForFolder(gomock.Any()).Return(true).AnyTimes()

			// Expect Scan to be called with baseFolderPath; FolderConfig is retrieved from context
			mockScanner.EXPECT().Scan(
				gomock.Any(),
				baseFolderPath, // pathToScan should be baseFolderPath
			).DoAndReturn(func(ctx context.Context, path types.FilePath) ([]types.Issue, error) {
				cfg, ok := ctx2.FolderConfigFromContext(ctx)
				require.True(t, ok)
				require.NotNil(t, cfg)
				// Verify the config passed has the correct values
				assert.Equal(t, baseFolderPath, cfg.FolderPath, "folderConfig.FolderPath should be baseFolderPath")
				assert.Equal(t, expectedOrg, cfg.PreferredOrg(), "folderConfig.PreferredOrg should be preserved")
				return []types.Issue{}, nil
			}).Times(1)

			dcs := setupScannerWithMock(t, engine, tokenService, mockScanner)

			// Act
			err := dcs.scanBaseBranch(t.Context(), mockScanner, folderConfig, nil)

			// Check that there was no error. Note the actual test behavior is verified by the mock scanner.
			require.NoError(t, err)
		})
	}
}

func TestScanBaseBranch_PreservesOriginalFolderConfig(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Setup - use real temp dirs for path validation
	workspacePath := types.FilePath(t.TempDir())
	baseFolderPath := types.FilePath(t.TempDir())
	expectedOrg := "test-org"

	folderConfig := &types.FolderConfig{FolderPath: workspacePath}
	syncFolderToConfig(t, engine, folderConfig, &syncFolderOpts{
		ReferenceFolderPath: baseFolderPath,
		PreferredOrg:        expectedOrg,
		OrgSetByUser:        true,
	})

	mockScanner := mock_types.NewMockProductScanner(ctrl)
	mockScanner.EXPECT().Product().Return(product.ProductOpenSource).AnyTimes()
	mockScanner.EXPECT().IsEnabledForFolder(gomock.Any()).Return(true).AnyTimes()
	mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).Return([]types.Issue{}, nil).Times(1)

	dcs := setupScannerWithMock(t, engine, tokenService, mockScanner)

	// Act
	err := dcs.scanBaseBranch(t.Context(), mockScanner, folderConfig, nil)

	require.NoError(t, err)

	// Verify original folderConfig was NOT modified
	assert.Equal(t, workspacePath, folderConfig.FolderPath, "Original folderConfig.FolderPath should not be modified")
	assert.Equal(t, baseFolderPath, folderConfig.ReferenceFolderPath(), "Original folderConfig.ReferenceFolderPath should not be modified")
}

func TestScanBaseBranch_NilFolderConfig_ReturnsError(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockScanner := mock_types.NewMockProductScanner(ctrl)
	mockScanner.EXPECT().Product().Return(product.ProductOpenSource).AnyTimes()
	mockScanner.EXPECT().IsEnabledForFolder(gomock.Any()).Return(true).AnyTimes()
	// Scan should NOT be called when folderConfig is nil
	mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).Times(0)

	dcs := setupScannerWithMock(t, engine, tokenService, mockScanner)

	// Act
	err := dcs.scanBaseBranch(t.Context(), mockScanner, nil, nil)

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "folder config is required")
}

func TestScanBaseBranch_SkipsWhenSnapshotExists(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Setup - use real temp dirs for path validation
	workspacePath := types.FilePath(t.TempDir())
	baseFolderPath := types.FilePath(t.TempDir())

	folderConfig := &types.FolderConfig{FolderPath: workspacePath}
	syncFolderToConfig(t, engine, folderConfig, &syncFolderOpts{ReferenceFolderPath: baseFolderPath})

	mockScanner := mock_types.NewMockProductScanner(ctrl)
	mockScanner.EXPECT().Product().Return(product.ProductOpenSource).AnyTimes()
	mockScanner.EXPECT().IsEnabledForFolder(gomock.Any()).Return(true).AnyTimes()
	// Scan should NOT be called when snapshot exists
	mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).Times(0)

	// Create a mock persister that reports snapshot exists
	mockPersister := mock_persistence.NewMockScanSnapshotPersister(ctrl)
	mockPersister.EXPECT().Exists(gomock.Any(), gomock.Any(), gomock.Any()).Return(true).AnyTimes()

	dcs := setupScannerWithMock(t, engine, tokenService, mockScanner)
	dcs.scanPersister = mockPersister

	// Act
	err := dcs.scanBaseBranch(t.Context(), mockScanner, folderConfig, nil)

	// Check that there was no error. Note the actual test behavior is verified by the mock scanner.
	require.NoError(t, err)
}

func TestScanBaseBranch_AllProducts_UseCorrectOrgFromFolderConfig(t *testing.T) {
	products := []product.Product{
		product.ProductCode,
		product.ProductOpenSource,
		product.ProductInfrastructureAsCode,
	}

	for _, p := range products {
		t.Run(string(p), func(t *testing.T) {
			engine, tokenService := testutil.UnitTestWithEngine(t)
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Use real temp dirs for path validation
			workspacePath := types.FilePath(t.TempDir())
			baseFolderPath := types.FilePath(t.TempDir())
			expectedOrg := "org-for-" + string(p)

			folderConfig := &types.FolderConfig{FolderPath: workspacePath}
			syncFolderToConfig(t, engine, folderConfig, &syncFolderOpts{
				ReferenceFolderPath: baseFolderPath,
				PreferredOrg:        expectedOrg,
				OrgSetByUser:        true,
			})

			mockScanner := mock_types.NewMockProductScanner(ctrl)
			mockScanner.EXPECT().Product().Return(p).AnyTimes()
			mockScanner.EXPECT().IsEnabledForFolder(gomock.Any()).Return(true).AnyTimes()

			// Expect Scan to be called and verify the org is correctly passed and resolved
			mockScanner.EXPECT().Scan(
				gomock.Any(),
				gomock.Any(),
			).DoAndReturn(func(ctx context.Context, _ types.FilePath) ([]types.Issue, error) {
				cfg, ok := ctx2.FolderConfigFromContext(ctx)
				require.True(t, ok)
				require.NotNil(t, cfg)
				// Verify the config has the correct org
				assert.Equal(t, expectedOrg, cfg.PreferredOrg(), "Scanner should receive the org from folderConfig")
				fConf := cfg.Conf()
				if fConf == nil {
					fConf = engine.GetConfiguration()
				}
				resolvedOrg := config.FolderOrganizationFromConfig(fConf, cfg.FolderPath, engine.GetLogger())
				assert.Equal(t, expectedOrg, resolvedOrg, "Scanner should resolve the expected org")
				return []types.Issue{}, nil
			}).Times(1)

			dcs := setupScannerWithMock(t, engine, tokenService, mockScanner)

			// Act
			err := dcs.scanBaseBranch(t.Context(), mockScanner, folderConfig, nil)

			// Check that there was no error. Note the actual test behavior is verified by the mock scanner.
			require.NoError(t, err)
		})
	}
}

func TestScanBaseBranch_ClassifiesMissingReference(t *testing.T) {
	gitRepo := func(t *testing.T) types.FilePath {
		t.Helper()
		dir := t.TempDir()
		testsupport.InitTestGitRepo(t, dir)
		return types.FilePath(dir)
	}
	plainDir := func(t *testing.T) types.FilePath {
		t.Helper()
		return types.FilePath(t.TempDir())
	}

	testCases := []struct {
		name       string
		folder     func(t *testing.T) types.FilePath
		baseBranch string
		want       error
	}{
		{name: "folder that isn't a git repository", folder: plainDir, want: ErrNotGitRepo},
		{name: "git repository without a base branch", folder: gitRepo, want: ErrMissingDeltaReference},
		{name: "saved base branch missing locally", folder: gitRepo, baseBranch: "deleted-branch", want: ErrBaseBranchNotFound},
		{name: "saved base branch exists locally", folder: gitRepo, baseBranch: "main", want: nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			engine, tokenService := testutil.UnitTestWithEngine(t)
			ctrl := gomock.NewController(t)

			folderConfig := &types.FolderConfig{FolderPath: tc.folder(t)}
			syncFolderToConfig(t, engine, folderConfig, &syncFolderOpts{BaseBranch: tc.baseBranch})

			mockScanner := mock_types.NewMockProductScanner(ctrl)
			mockScanner.EXPECT().Product().Return(product.ProductCode).AnyTimes()
			mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).Times(0)

			mockPersister := mock_persistence.NewMockScanSnapshotPersister(ctrl)
			mockPersister.EXPECT().Exists(gomock.Any(), gomock.Any(), gomock.Any()).Return(true).AnyTimes()

			dcs := setupScannerWithMock(t, engine, tokenService, mockScanner)
			dcs.scanPersister = mockPersister

			err := dcs.scanBaseBranch(t.Context(), mockScanner, folderConfig, nil)

			assert.Equal(t, tc.want, err, "classification matches the exact, unwrapped error")
		})
	}
}

func TestScan_MissingDeltaReference_LogsNoError(t *testing.T) {
	testCases := []struct {
		name       string
		gitRepo    bool
		baseBranch string
	}{
		{name: "folder that isn't a git repository"},
		{name: "git repository without a base branch", gitRepo: true},
		{name: "saved base branch missing locally", gitRepo: true, baseBranch: "deleted-branch"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			engine, tokenService := testutil.UnitTestWithEngine(t)
			var mu sync.Mutex
			var errorLogs []string
			logger := engine.GetLogger().Hook(zerolog.HookFunc(func(_ *zerolog.Event, level zerolog.Level, msg string) {
				if level >= zerolog.ErrorLevel {
					mu.Lock()
					defer mu.Unlock()
					errorLogs = append(errorLogs, msg)
				}
			}))
			engine.SetLogger(&logger)

			dir := t.TempDir()
			if tc.gitRepo {
				testsupport.InitTestGitRepo(t, dir)
			}
			folderConfig := &types.FolderConfig{FolderPath: types.FilePath(dir)}
			syncFolderToConfig(t, engine, folderConfig, &syncFolderOpts{BaseBranch: tc.baseBranch})

			ctrl := gomock.NewController(t)
			mockScanner := mock_types.NewMockProductScanner(ctrl)
			mockScanner.EXPECT().Product().Return(product.ProductCode).AnyTimes()
			mockScanner.EXPECT().IsEnabledForFolder(gomock.Any()).Return(true).AnyTimes()
			mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).Return([]types.Issue{}, nil).Times(1)
			sc, _ := setupScanner(t, engine, tokenService, mockScanner)

			sc.Scan(ctx2.NewContextWithFolderConfig(t.Context(), folderConfig), folderConfig.FolderPath, types.NoopResultProcessor, nil)

			mu.Lock()
			defer mu.Unlock()
			for _, msg := range errorLogs {
				assert.NotRegexp(t, `(?i)base branch|reference`, msg)
			}
		})
	}
}

func TestScan_DeltaOn_WorkingTreeResultCarriesCurrentReferenceState(t *testing.T) {
	cloneFailed := errors.New("clone failed")
	testCases := []struct {
		name            string
		gitRepo         bool
		baseBranch      string
		referenceFolder bool
		fileSave        bool
		previousRefErr  error
		want            error
	}{
		{name: "first scan of a folder that isn't a git repository", want: ErrNotGitRepo},
		{name: "first scan of a git repository without a base branch", gitRepo: true, want: ErrMissingDeltaReference},
		{name: "first scan with a saved base branch missing locally", gitRepo: true, baseBranch: "deleted-branch", want: ErrBaseBranchNotFound},
		{name: "file save in a git repository without a base branch", gitRepo: true, fileSave: true, want: ErrMissingDeltaReference},
		{name: "full scan with a usable reference after a failed reference scan", referenceFolder: true, previousRefErr: cloneFailed, want: nil},
		{name: "full scan with a picked base branch after a missing one", gitRepo: true, baseBranch: "main", previousRefErr: ErrMissingDeltaReference, want: nil},
		{name: "file save with a usable reference keeps the last reference result", referenceFolder: true, fileSave: true, previousRefErr: cloneFailed, want: cloneFailed},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			engine, tokenService := testutil.UnitTestWithEngine(t)

			dir := t.TempDir()
			if tc.gitRepo {
				testsupport.InitTestGitRepo(t, dir)
			}
			folderPath := types.FilePath(dir)
			opts := &syncFolderOpts{BaseBranch: tc.baseBranch, UserOverrides: map[string]any{types.SettingScanNetNew: true}}
			if tc.referenceFolder {
				refDir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(refDir, "baseline.txt"), []byte("baseline"), 0o600))
				opts.ReferenceFolderPath = types.FilePath(refDir)
			}
			folderConfig := &types.FolderConfig{FolderPath: folderPath}
			syncFolderToConfig(t, engine, folderConfig, opts)
			resolver := defaultResolver(t, engine)
			require.True(t, resolver.IsDeltaFindingsEnabledForFolder(folderConfig))

			agg := scanstates.NewScanStateAggregator(engine.GetConfiguration(), engine.GetLogger(), &scanstates.NoopEmitter{}, resolver, engine)
			agg.Init([]types.FilePath{folderPath})
			if tc.previousRefErr != nil {
				agg.SetScanDone(folderPath, product.ProductCode, true, tc.previousRefErr)
			}

			ctrl := gomock.NewController(t)
			mockScanner := mock_types.NewMockProductScanner(ctrl)
			mockScanner.EXPECT().Product().Return(product.ProductCode).AnyTimes()
			mockScanner.EXPECT().IsEnabledForFolder(gomock.Any()).Return(true).AnyTimes()
			mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).Return([]types.Issue{}, nil).AnyTimes()
			sc, _ := setupScannerWithResolverAndAgg(t, engine, tokenService, resolver, agg, mockScanner)

			var published bool
			var refErrAtPublish error
			captureProcessor := func(_ context.Context, data types.ScanData) {
				if !data.IsReferenceScan {
					published = true
					refErrAtPublish = agg.GetScanErr(folderPath, product.ProductCode, true)
				}
			}

			pathToScan := folderPath
			if tc.fileSave {
				pathToScan = types.FilePath(filepath.Join(dir, "main.go"))
			}
			sc.Scan(ctx2.NewContextWithFolderConfig(t.Context(), folderConfig), pathToScan, captureProcessor, nil)

			require.True(t, published)
			assert.Equal(t, tc.want, refErrAtPublish, "the working-tree $/snyk.scan reports the current reference state")
		})
	}
}

// setupScannerWithMock creates a scanner with a mock ProductScanner for testing
func setupScannerWithMock(t *testing.T, engine workflow.Engine, tokenService types.TokenService, mockScanner *mock_types.MockProductScanner) *DelegatingConcurrentScanner {
	t.Helper()
	scanner, _ := setupScanner(t, engine, tokenService, mockScanner)
	return scanner.(*DelegatingConcurrentScanner)
}
