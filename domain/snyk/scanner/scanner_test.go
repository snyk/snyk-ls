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

package scanner

import (
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/initialize"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

func TestScan_UsesEnabledProductLinesOnly(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	enabledScanner := mock_types.NewMockProductScanner(ctrl)
	enabledScanner.EXPECT().Product().Return(product.ProductCode).AnyTimes()
	enabledScanner.EXPECT().IsEnabled().Return(true).AnyTimes()
	enabledScanner.EXPECT().Scan(gomock.Any(), gomock.Any(), gomock.Any()).Return([]types.Issue{}, nil).Times(1)

	disabledScanner := mock_types.NewMockProductScanner(ctrl)
	disabledScanner.EXPECT().Product().Return(product.ProductOpenSource).AnyTimes()
	disabledScanner.EXPECT().IsEnabled().Return(false).MinTimes(1)
	// Explicitly verify Scan is NOT called on disabled scanner
	disabledScanner.EXPECT().Scan(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

	scanner, _ := setupScanner(t, c, enabledScanner, disabledScanner)

	scanner.Scan(t.Context(), "", types.NoopResultProcessor, &types.FolderConfig{FolderPath: ""})

	// gomock will verify expectations automatically
}

func setupScanner(t *testing.T, c *config.Config, testProductScanners ...types.ProductScanner) (
	sc Scanner,
	scanNotifier ScanNotifier,
) {
	t.Helper()
	scanNotifier = NewMockScanNotifier()
	notifier := notification.NewNotifier()
	apiClient := &snyk_api.FakeApiClient{CodeEnabled: false}
	persister := persistence.NewNopScanPersister()
	scanStateAggregator := scanstates.NewNoopStateAggregator()
	er := error_reporting.NewTestErrorReporter()
	authenticationProvider := authentication.NewFakeCliAuthenticationProvider(c)
	authenticationProvider.IsAuthenticated = true
	authenticationService := authentication.NewAuthenticationService(c, authenticationProvider, er, notifier)
	sc = NewDelegatingScanner(c, initialize.NewDelegatingInitializer(), performance.NewInstrumentor(), scanNotifier, apiClient, authenticationService, notifier, persister, scanStateAggregator, testProductScanners...)
	return sc, scanNotifier
}

func Test_userNotAuthenticated_ScanSkipped(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	// Arrange
	mockScanner := mock_types.NewMockProductScanner(ctrl)
	mockScanner.EXPECT().Product().Return(product.ProductOpenSource).AnyTimes()
	mockScanner.EXPECT().IsEnabled().Return(true).AnyTimes()
	// Explicitly expect Scan to NOT be called when not authenticated
	mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

	scanner, _ := setupScanner(t, c, mockScanner)
	c.SetToken("")

	// Act
	scanner.Scan(t.Context(), "", types.NoopResultProcessor, &types.FolderConfig{FolderPath: ""})

	// Assert - gomock will fail if Scan was called
}

func Test_ScanStarted_TokenChanged_ScanCancelled(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	// Arrange - start with a valid token so scan begins
	c.SetToken(uuid.New().String())
	scanStarted := make(chan bool)
	wasCanceled := false

	mockScanner := mock_types.NewMockProductScanner(ctrl)
	mockScanner.EXPECT().Product().Return(product.ProductOpenSource).AnyTimes()
	mockScanner.EXPECT().IsEnabled().Return(true).AnyTimes()
	mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx interface{}, _ types.FilePath, _ *types.FolderConfig) ([]types.Issue, error) {
			scanStarted <- true
			// Simulate slow scan - wait for context cancellation or timeout
			select {
			case <-ctx.(interface{ Done() <-chan struct{} }).Done():
				wasCanceled = true
			case <-time.After(2 * time.Second):
				// Scan completed normally (should not happen in this test)
			}
			return []types.Issue{}, nil
		}).Times(1)

	scanner, _ := setupScanner(t, c, mockScanner)
	done := make(chan bool)

	// Act
	go func() {
		scanner.Scan(t.Context(), "", types.NoopResultProcessor, &types.FolderConfig{FolderPath: ""})
		done <- true
	}()

	// Wait for scan to start, then change token to trigger cancellation
	testsupport.RequireEventuallyReceive(t, scanStarted, 5*time.Second, 10*time.Millisecond, "scan should start")
	c.SetToken(uuid.New().String())

	// Wait for scan to complete
	testsupport.RequireEventuallyReceive(t, done, 5*time.Second, 10*time.Millisecond, "scan should complete")

	// Assert - verify the scan was canceled, not timed out
	assert.True(t, wasCanceled, "Scan should have been canceled when token changed")
}

func TestScan_whenProductScannerEnabled_SendsInProgress(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	c.SetSnykCodeEnabled(true)
	mockScanner := mock_types.NewMockProductScanner(ctrl)
	mockScanner.EXPECT().Product().Return(product.ProductCode).AnyTimes()
	mockScanner.EXPECT().IsEnabled().Return(true).AnyTimes()
	// Expect exactly one scan call
	mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any(), gomock.Any()).Return([]types.Issue{}, nil).Times(1)

	sc, scanNotifier := setupScanner(t, c, mockScanner)
	mockScanNotifier := scanNotifier.(*MockScanNotifier)

	sc.Scan(t.Context(), "", types.NoopResultProcessor, &types.FolderConfig{FolderPath: ""})

	// Verify InProgress notification was sent
	assert.NotEmpty(t, mockScanNotifier.InProgressCalls(), "InProgress should be called when scan starts")
}

func TestDelegatingConcurrentScanner_executePreScanCommand(t *testing.T) {
	testsupport.NotOnWindows(t, "/bin/ls does not exist on windows")
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	c.SetSnykOssEnabled(true)
	p := product.ProductOpenSource
	mockScanner := mock_types.NewMockProductScanner(ctrl)
	mockScanner.EXPECT().Product().Return(p).AnyTimes()
	mockScanner.EXPECT().IsEnabled().Return(true).AnyTimes()

	sc, _ := setupScanner(t, c, mockScanner)
	delegatingScanner, ok := sc.(*DelegatingConcurrentScanner)
	require.True(t, ok)
	workDir := types.FilePath(t.TempDir())

	command := "/bin/sh"

	// setup folder config for prescan
	folderConfig := c.FolderConfig(workDir)
	scanCommandConfigMap := make(map[product.Product]types.ScanCommandConfig)
	scanCommandConfigMap[product.ProductOpenSource] = types.ScanCommandConfig{
		PreScanCommand:             command,
		PreScanOnlyReferenceFolder: false,
	}
	folderConfig.ScanCommandConfig = scanCommandConfigMap
	require.NoError(t, storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), folderConfig, c.Logger()))

	// trigger execute
	err := delegatingScanner.executePreScanCommand(t.Context(), c, p, folderConfig, workDir, false)
	require.NoError(t, err)
}

func TestScan_FileScan_UsesFolderConfigOrganization(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Setup folder config with specific organization
	folderPath := types.FilePath("/workspace/project")
	expectedOrg := "test-org-123"
	folderConfig := &types.FolderConfig{
		FolderPath:   folderPath,
		PreferredOrg: expectedOrg,
	}

	// Setup mock scanner that verifies the folderConfig
	mockScanner := mock_types.NewMockProductScanner(ctrl)
	mockScanner.EXPECT().Product().Return(product.ProductOpenSource).AnyTimes()
	mockScanner.EXPECT().IsEnabled().Return(true).AnyTimes()
	mockScanner.EXPECT().Scan(
		gomock.Any(),
		gomock.Any(),
		gomock.Any(),
	).DoAndReturn(func(_ interface{}, _ types.FilePath, cfg *types.FolderConfig) ([]types.Issue, error) {
		// Verify the product scanner received the correct folderConfig
		require.NotNil(t, cfg, "folderConfig should be passed to product scanner")
		assert.Equal(t, folderPath, cfg.FolderPath, "folderConfig.FolderPath should match")
		assert.Equal(t, expectedOrg, cfg.PreferredOrg, "folderConfig organization should match")
		return []types.Issue{}, nil
	}).Times(1)

	scanner, _ := setupScanner(t, c, mockScanner)

	// Scan a single file within the folder
	filePath := types.FilePath("/workspace/project/src/main.go")
	scanner.Scan(t.Context(), filePath, types.NoopResultProcessor, folderConfig)
}

func TestScan_FileScan_DifferentFoldersUseDifferentOrganizations(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Setup two folder configs with different organizations
	folderPath1 := types.FilePath("/workspace/project1")
	folderPath2 := types.FilePath("/workspace/project2")
	org1 := "org-for-project1"
	org2 := "org-for-project2"

	folderConfig1 := &types.FolderConfig{FolderPath: folderPath1, PreferredOrg: org1}
	folderConfig2 := &types.FolderConfig{FolderPath: folderPath2, PreferredOrg: org2}

	// Track received configs
	var receivedConfigs []*types.FolderConfig

	// Setup mock scanner
	mockScanner := mock_types.NewMockProductScanner(ctrl)
	mockScanner.EXPECT().Product().Return(product.ProductOpenSource).AnyTimes()
	mockScanner.EXPECT().IsEnabled().Return(true).AnyTimes()
	mockScanner.EXPECT().Scan(
		gomock.Any(),
		gomock.Any(),
		gomock.Any(),
	).DoAndReturn(func(_ interface{}, _ types.FilePath, cfg *types.FolderConfig) ([]types.Issue, error) {
		receivedConfigs = append(receivedConfigs, cfg)
		return []types.Issue{}, nil
	}).Times(2)

	scanner, _ := setupScanner(t, c, mockScanner)

	// Scan file in folder 1
	scanner.Scan(t.Context(), types.FilePath("/workspace/project1/file1.go"), types.NoopResultProcessor, folderConfig1)

	// Scan file in folder 2
	scanner.Scan(t.Context(), types.FilePath("/workspace/project2/file2.go"), types.NoopResultProcessor, folderConfig2)

	// Verify both configs were received with correct orgs
	require.Len(t, receivedConfigs, 2)
	assert.Equal(t, org1, receivedConfigs[0].PreferredOrg, "First scan should use org1")
	assert.Equal(t, folderPath1, receivedConfigs[0].FolderPath, "First scan should use folderPath1")
	assert.Equal(t, org2, receivedConfigs[1].PreferredOrg, "Second scan should use org2")
	assert.Equal(t, folderPath2, receivedConfigs[1].FolderPath, "Second scan should use folderPath2")
}

func TestScan_FileScan_PathIsSeparateFromFolderPath(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Setup folder config
	folderPath := types.FilePath("/workspace/project")
	folderConfig := &types.FolderConfig{FolderPath: folderPath}

	// Scan a specific file (not the folder itself)
	filePath := types.FilePath("/workspace/project/src/deep/nested/file.go")

	// Setup mock scanner that verifies both path and folderConfig
	mockScanner := mock_types.NewMockProductScanner(ctrl)
	mockScanner.EXPECT().Product().Return(product.ProductOpenSource).AnyTimes()
	mockScanner.EXPECT().IsEnabled().Return(true).AnyTimes()
	mockScanner.EXPECT().Scan(
		gomock.Any(),
		filePath,
		gomock.Any(),
	).DoAndReturn(func(_ interface{}, path types.FilePath, cfg *types.FolderConfig) ([]types.Issue, error) {
		assert.Equal(t, filePath, path, "path should be the file being scanned")
		assert.Equal(t, folderPath, cfg.FolderPath, "folderConfig.FolderPath should be the workspace folder")
		return []types.Issue{}, nil
	}).Times(1)

	scanner, _ := setupScanner(t, c, mockScanner)

	scanner.Scan(t.Context(), filePath, types.NoopResultProcessor, folderConfig)
}

func TestDelegatingConcurrentScanner_getPersistHash_ErrorOnMissingReference(t *testing.T) {
	c := testutil.UnitTest(t)

	dcs := &DelegatingConcurrentScanner{
		c: c,
	}

	folderConfig := &types.FolderConfig{
		ReferenceFolderPath: "",
		BaseBranch:          "",
	}

	// Act
	_, err := dcs.getPersistHash(folderConfig)

	// Assert
	assert.ErrorIs(t, err, ErrMissingDeltaReference)
}
