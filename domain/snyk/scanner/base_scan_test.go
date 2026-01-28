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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestScanBaseBranch_AllProducts_ReceiveCorrectPathAndFolderPath(t *testing.T) {
	testCases := []struct {
		name         string
		product      product.Product
		expectedPath func(baseFolderPath types.FilePath) types.FilePath
	}{
		{
			name:    "Code scanner receives empty path for folder scan",
			product: product.ProductCode,
			expectedPath: func(_ types.FilePath) types.FilePath {
				return types.FilePath("")
			},
		},
		{
			name:    "OSS scanner receives baseFolderPath as path",
			product: product.ProductOpenSource,
			expectedPath: func(baseFolderPath types.FilePath) types.FilePath {
				return baseFolderPath
			},
		},
		{
			name:    "IaC scanner receives baseFolderPath as path",
			product: product.ProductInfrastructureAsCode,
			expectedPath: func(baseFolderPath types.FilePath) types.FilePath {
				return baseFolderPath
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := testutil.UnitTest(t)

			// Setup - use real temp dirs for path validation
			workspacePath := types.FilePath(t.TempDir())
			baseFolderPath := types.FilePath(t.TempDir())
			expectedOrg := "test-org"

			folderConfig := &types.FolderConfig{
				FolderPath:          workspacePath,
				ReferenceFolderPath: baseFolderPath,
				PreferredOrg:        expectedOrg,
			}

			productScanner := NewTestProductScanner(tc.product, true)
			scanner, _ := setupScanner(t, c, productScanner)
			dcs := scanner.(*DelegatingConcurrentScanner)

			// Act
			err := dcs.scanBaseBranch(t.Context(), productScanner, folderConfig, nil)

			// Assert
			require.NoError(t, err)
			assert.Eventually(t, func() bool {
				return productScanner.Scans() == 1
			}, 1*time.Second, 10*time.Millisecond)

			// Verify scanner received correct path
			assert.Equal(t, tc.expectedPath(baseFolderPath), productScanner.LastPath())

			// Verify folderConfig.FolderPath was set to baseFolderPath
			receivedConfig := productScanner.LastFolderConfig()
			require.NotNil(t, receivedConfig)
			assert.Equal(t, baseFolderPath, receivedConfig.FolderPath)
			assert.Equal(t, expectedOrg, receivedConfig.PreferredOrg)
		})
	}
}

func TestScanBaseBranch_PreservesOriginalFolderConfig(t *testing.T) {
	c := testutil.UnitTest(t)

	// Setup - use real temp dirs for path validation
	workspacePath := types.FilePath(t.TempDir())
	baseFolderPath := types.FilePath(t.TempDir())
	expectedOrg := "test-org"

	folderConfig := &types.FolderConfig{
		FolderPath:          workspacePath,
		ReferenceFolderPath: baseFolderPath,
		PreferredOrg:        expectedOrg,
	}

	ossScanner := NewTestProductScanner(product.ProductOpenSource, true)
	scanner, _ := setupScanner(t, c, ossScanner)
	dcs := scanner.(*DelegatingConcurrentScanner)

	// Act
	err := dcs.scanBaseBranch(t.Context(), ossScanner, folderConfig, nil)

	// Assert
	require.NoError(t, err)
	assert.Eventually(t, func() bool {
		return ossScanner.Scans() == 1
	}, 1*time.Second, 10*time.Millisecond)

	// Verify original folderConfig was NOT modified
	assert.Equal(t, workspacePath, folderConfig.FolderPath, "Original folderConfig.FolderPath should not be modified")
	assert.Equal(t, baseFolderPath, folderConfig.ReferenceFolderPath, "Original folderConfig.ReferenceFolderPath should not be modified")
}

func TestScanBaseBranch_NilFolderConfig_ReturnsError(t *testing.T) {
	c := testutil.UnitTest(t)

	ossScanner := NewTestProductScanner(product.ProductOpenSource, true)
	scanner, _ := setupScanner(t, c, ossScanner)
	dcs := scanner.(*DelegatingConcurrentScanner)

	// Act
	err := dcs.scanBaseBranch(t.Context(), ossScanner, nil, nil)

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "folder config is required")
	assert.Equal(t, 0, ossScanner.Scans(), "Scanner should not be called when folderConfig is nil")
}

func TestScanBaseBranch_SkipsWhenSnapshotExists(t *testing.T) {
	c := testutil.UnitTest(t)

	// Setup - use real temp dirs for path validation
	workspacePath := types.FilePath(t.TempDir())
	baseFolderPath := types.FilePath(t.TempDir())

	folderConfig := &types.FolderConfig{
		FolderPath:          workspacePath,
		ReferenceFolderPath: baseFolderPath,
	}

	ossScanner := NewTestProductScanner(product.ProductOpenSource, true)

	// Create a persister that reports snapshot exists
	persister := &mockScanPersister{existsResult: true}

	scanner, _ := setupScanner(t, c, ossScanner)
	dcs := scanner.(*DelegatingConcurrentScanner)
	dcs.scanPersister = persister

	// Act
	err := dcs.scanBaseBranch(t.Context(), ossScanner, folderConfig, nil)

	// Assert
	require.NoError(t, err)
	// Give some time for potential async operations
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 0, ossScanner.Scans(), "Scanner should not be called when snapshot exists")
}

func TestScanBaseBranch_AllProducts_UseCorrectOrgFromFolderConfig(t *testing.T) {
	c := testutil.UnitTest(t)

	products := []product.Product{
		product.ProductCode,
		product.ProductOpenSource,
		product.ProductInfrastructureAsCode,
	}

	for _, p := range products {
		t.Run(string(p), func(t *testing.T) {
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

			productScanner := NewTestProductScanner(p, true)
			scanner, _ := setupScanner(t, c, productScanner)
			dcs := scanner.(*DelegatingConcurrentScanner)

			// Act
			err := dcs.scanBaseBranch(t.Context(), productScanner, folderConfig, nil)

			// Assert
			require.NoError(t, err)
			assert.Eventually(t, func() bool {
				return productScanner.Scans() == 1
			}, 1*time.Second, 10*time.Millisecond)

			receivedConfig := productScanner.LastFolderConfig()
			require.NotNil(t, receivedConfig)
			assert.Equal(t, expectedOrg, receivedConfig.PreferredOrg, "Scanner should receive the org from folderConfig")
		})
	}
}

// mockScanPersister is a test double for ScanSnapshotPersister
type mockScanPersister struct {
	existsResult bool
	addedIssues  []types.Issue
}

func (m *mockScanPersister) Exists(_ types.FilePath, _ string, _ product.Product) bool {
	return m.existsResult
}

func (m *mockScanPersister) Clear(_ []types.FilePath, _ bool) {}

func (m *mockScanPersister) ClearFolder(_ types.FilePath) {}

func (m *mockScanPersister) Init(_ []types.FilePath) error {
	return nil
}

func (m *mockScanPersister) Add(_ types.FilePath, _ string, issues []types.Issue, _ product.Product) error {
	m.addedIssues = issues
	return nil
}

func (m *mockScanPersister) GetPersistedIssueList(_ types.FilePath, _ product.Product) ([]types.Issue, error) {
	return nil, nil
}

var _ persistence.ScanSnapshotPersister = (*mockScanPersister)(nil)
