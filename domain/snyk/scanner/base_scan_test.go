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
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk/persistence/mock_persistence"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

func TestScanBaseBranch_AllProducts_ReceiveCorrectPathAndFolderPath(t *testing.T) {
	// All scanners now receive baseFolderPath as objectToScan.
	// The Code scanner determines it's a full workspace scan because objectToScan == workspaceFolderConfig.FolderPath.
	testCases := []struct {
		name    string
		product product.Product
	}{
		{name: "Code scanner receives baseFolderPath as objectToScan", product: product.ProductCode},
		{name: "OSS scanner receives baseFolderPath as objectToScan", product: product.ProductOpenSource},
		{name: "IaC scanner receives baseFolderPath as objectToScan", product: product.ProductInfrastructureAsCode},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := testutil.UnitTest(t)
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Setup - use real temp dirs for path validation
			workspacePath := types.FilePath(t.TempDir())
			baseFolderPath := types.FilePath(t.TempDir())
			expectedOrg := "test-org"

			folderConfig := &types.FolderConfig{
				FolderPath:          workspacePath,
				ReferenceFolderPath: baseFolderPath,
				PreferredOrg:        expectedOrg,
			}

			// Create mock scanner with expectations
			mockScanner := mock_types.NewMockProductScanner(ctrl)
			mockScanner.EXPECT().Product().Return(tc.product).AnyTimes()
			mockScanner.EXPECT().IsEnabled().Return(true).AnyTimes()

			// Expect Scan to be called with baseFolderPath and a config where FolderPath == baseFolderPath
			mockScanner.EXPECT().Scan(
				gomock.Any(),
				baseFolderPath, // objectToScan should be baseFolderPath
				gomock.Any(),   // workspaceFolderConfig
			).DoAndReturn(func(_ interface{}, path types.FilePath, cfg *types.FolderConfig) ([]types.Issue, error) {
				// Verify the config passed has the correct values
				assert.Equal(t, baseFolderPath, cfg.FolderPath, "folderConfig.FolderPath should be baseFolderPath")
				assert.Equal(t, expectedOrg, cfg.PreferredOrg, "folderConfig.PreferredOrg should be preserved")
				return []types.Issue{}, nil
			}).Times(1)

			scanner, _ := setupScannerWithMock(t, c, ctrl, mockScanner)
			dcs := scanner.(*DelegatingConcurrentScanner)

			// Act
			err := dcs.scanBaseBranch(t.Context(), mockScanner, folderConfig, nil)

			// Assert
			require.NoError(t, err)
		})
	}
}

func TestScanBaseBranch_PreservesOriginalFolderConfig(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Setup - use real temp dirs for path validation
	workspacePath := types.FilePath(t.TempDir())
	baseFolderPath := types.FilePath(t.TempDir())
	expectedOrg := "test-org"

	folderConfig := &types.FolderConfig{
		FolderPath:          workspacePath,
		ReferenceFolderPath: baseFolderPath,
		PreferredOrg:        expectedOrg,
	}

	mockScanner := mock_types.NewMockProductScanner(ctrl)
	mockScanner.EXPECT().Product().Return(product.ProductOpenSource).AnyTimes()
	mockScanner.EXPECT().IsEnabled().Return(true).AnyTimes()
	mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any(), gomock.Any()).Return([]types.Issue{}, nil).Times(1)

	scanner, _ := setupScannerWithMock(t, c, ctrl, mockScanner)
	dcs := scanner.(*DelegatingConcurrentScanner)

	// Act
	err := dcs.scanBaseBranch(t.Context(), mockScanner, folderConfig, nil)

	// Assert
	require.NoError(t, err)
	// Verify original folderConfig was NOT modified
	assert.Equal(t, workspacePath, folderConfig.FolderPath, "Original folderConfig.FolderPath should not be modified")
	assert.Equal(t, baseFolderPath, folderConfig.ReferenceFolderPath, "Original folderConfig.ReferenceFolderPath should not be modified")
}

func TestScanBaseBranch_NilFolderConfig_ReturnsError(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockScanner := mock_types.NewMockProductScanner(ctrl)
	mockScanner.EXPECT().Product().Return(product.ProductOpenSource).AnyTimes()
	mockScanner.EXPECT().IsEnabled().Return(true).AnyTimes()
	// Scan should NOT be called when folderConfig is nil

	scanner, _ := setupScannerWithMock(t, c, ctrl, mockScanner)
	dcs := scanner.(*DelegatingConcurrentScanner)

	// Act
	err := dcs.scanBaseBranch(t.Context(), mockScanner, nil, nil)

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "folder config is required")
}

func TestScanBaseBranch_SkipsWhenSnapshotExists(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Setup - use real temp dirs for path validation
	workspacePath := types.FilePath(t.TempDir())
	baseFolderPath := types.FilePath(t.TempDir())

	folderConfig := &types.FolderConfig{
		FolderPath:          workspacePath,
		ReferenceFolderPath: baseFolderPath,
	}

	mockScanner := mock_types.NewMockProductScanner(ctrl)
	mockScanner.EXPECT().Product().Return(product.ProductOpenSource).AnyTimes()
	mockScanner.EXPECT().IsEnabled().Return(true).AnyTimes()
	// Scan should NOT be called when snapshot exists

	// Create a mock persister that reports snapshot exists
	mockPersister := mock_persistence.NewMockScanSnapshotPersister(ctrl)
	mockPersister.EXPECT().Exists(gomock.Any(), gomock.Any(), gomock.Any()).Return(true).AnyTimes()

	scanner, _ := setupScannerWithMock(t, c, ctrl, mockScanner)
	dcs := scanner.(*DelegatingConcurrentScanner)
	dcs.scanPersister = mockPersister

	// Act
	err := dcs.scanBaseBranch(t.Context(), mockScanner, folderConfig, nil)

	// Assert
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
			c := testutil.UnitTest(t)
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Use real temp dirs for path validation
			workspacePath := types.FilePath(t.TempDir())
			baseFolderPath := types.FilePath(t.TempDir())
			expectedOrg := "org-for-" + string(p)

			folderConfig := &types.FolderConfig{
				FolderPath:          workspacePath,
				ReferenceFolderPath: baseFolderPath,
				PreferredOrg:        expectedOrg,
				OrgSetByUser:        true,
			}

			mockScanner := mock_types.NewMockProductScanner(ctrl)
			mockScanner.EXPECT().Product().Return(p).AnyTimes()
			mockScanner.EXPECT().IsEnabled().Return(true).AnyTimes()

			// Expect Scan to be called and verify the org is correctly passed and resolved
			mockScanner.EXPECT().Scan(
				gomock.Any(),
				gomock.Any(),
				gomock.Any(),
			).DoAndReturn(func(_ interface{}, _ types.FilePath, cfg *types.FolderConfig) ([]types.Issue, error) {
				// Verify the config has the correct org
				assert.Equal(t, expectedOrg, cfg.PreferredOrg, "Scanner should receive the org from folderConfig")
				// Verify that FolderConfigOrganization resolves correctly (simulating what real scanners do)
				resolvedOrg := c.FolderConfigOrganization(cfg)
				assert.Equal(t, expectedOrg, resolvedOrg, "Scanner should resolve the expected org")
				return []types.Issue{}, nil
			}).Times(1)

			scanner, _ := setupScannerWithMock(t, c, ctrl, mockScanner)
			dcs := scanner.(*DelegatingConcurrentScanner)

			// Act
			err := dcs.scanBaseBranch(t.Context(), mockScanner, folderConfig, nil)

			// Assert
			require.NoError(t, err)
		})
	}
}

// setupScannerWithMock creates a scanner with a mock ProductScanner for testing
func setupScannerWithMock(t *testing.T, c *config.Config, ctrl *gomock.Controller, mockScanner *mock_types.MockProductScanner) (Scanner, ScanNotifier) {
	t.Helper()
	return setupScanner(t, c, mockScanner)
}
