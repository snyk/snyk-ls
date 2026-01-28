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

	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/types"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/initialize"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestScan_UsesEnabledProductLinesOnly(t *testing.T) {
	c := testutil.UnitTest(t)
	enabledScanner := NewTestProductScanner(product.ProductCode, true)
	disabledScanner := NewTestProductScanner(product.ProductOpenSource, false)
	scanner, _ := setupScanner(t, c, enabledScanner, disabledScanner)

	scanner.Scan(t.Context(), "", types.NoopResultProcessor, &types.FolderConfig{FolderPath: ""})

	assert.Eventually(
		t,
		func() bool {
			return enabledScanner.Scans() == 1 && disabledScanner.Scans() == 0
		},
		1*time.Second,
		10*time.Millisecond,
	)
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
	// Arrange
	productScanner := NewTestProductScanner(product.ProductOpenSource, true)
	scanner, _ := setupScanner(t, c, productScanner)
	c.SetToken("")
	emptyToken := !c.NonEmptyToken()

	// Act
	scanner.Scan(t.Context(), "", types.NoopResultProcessor, &types.FolderConfig{FolderPath: ""})

	// Assert
	assert.True(t, emptyToken)
	assert.Equal(t, 0, productScanner.scans)
}

func Test_ScanStarted_TokenChanged_ScanCancelled(t *testing.T) {
	c := testutil.UnitTest(t)
	// Arrange
	c.SetToken("")
	productScanner := NewTestProductScanner(product.ProductOpenSource, true)
	productScanner.SetScanDuration(2 * time.Second)
	scanner, _ := setupScanner(t, c, productScanner)
	done := make(chan bool)

	// Act
	go func() {
		scanner.Scan(t.Context(), "", types.NoopResultProcessor, &types.FolderConfig{FolderPath: ""})
		done <- true
	}()
	time.Sleep(500 * time.Millisecond) // Wait for the product scanner to start running
	c.SetToken(uuid.New().String())

	// Assert
	// Need to wait for the scan to be done before checking whether the product scanner was used
	<-done

	assert.Zero(t, productScanner.scans)
}

func TestScan_whenProductScannerEnabled_SendsInProgress(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetSnykCodeEnabled(true)
	enabledScanner := NewTestProductScanner(product.ProductCode, true)
	sc, scanNotifier := setupScanner(t, c, enabledScanner)
	mockScanNotifier := scanNotifier.(*MockScanNotifier)

	sc.Scan(t.Context(), "", types.NoopResultProcessor, &types.FolderConfig{FolderPath: ""})

	assert.NotEmpty(t, mockScanNotifier.InProgressCalls())
}

func TestDelegatingConcurrentScanner_executePreScanCommand(t *testing.T) {
	testsupport.NotOnWindows(t, "/bin/ls does not exist on windows")
	c := testutil.UnitTest(t)
	c.SetSnykOssEnabled(true)
	p := product.ProductOpenSource
	enabledScanner := NewTestProductScanner(p, true)
	sc, _ := setupScanner(t, c, enabledScanner)
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

	// Setup folder config with specific organization
	folderPath := types.FilePath("/workspace/project")
	expectedOrg := "test-org-123"
	folderConfig := &types.FolderConfig{
		FolderPath:   folderPath,
		PreferredOrg: expectedOrg,
	}

	// Setup scanner that captures the folderConfig
	productScanner := NewTestProductScanner(product.ProductOpenSource, true)
	scanner, _ := setupScanner(t, c, productScanner)

	// Scan a single file within the folder
	filePath := types.FilePath("/workspace/project/src/main.go")
	scanner.Scan(t.Context(), filePath, types.NoopResultProcessor, folderConfig)

	// Wait for scan to complete
	assert.Eventually(t, func() bool {
		return productScanner.Scans() == 1
	}, 1*time.Second, 10*time.Millisecond)

	// Verify the product scanner received the correct folderConfig
	receivedConfig := productScanner.LastFolderConfig()
	require.NotNil(t, receivedConfig, "folderConfig should be passed to product scanner")
	assert.Equal(t, folderPath, receivedConfig.FolderPath, "folderConfig.FolderPath should match")
	assert.Equal(t, expectedOrg, receivedConfig.PreferredOrg, "folderConfig organization should match")
}

func TestScan_FileScan_DifferentFoldersUseDifferentOrganizations(t *testing.T) {
	c := testutil.UnitTest(t)

	// Setup two folder configs with different organizations
	folderPath1 := types.FilePath("/workspace/project1")
	folderPath2 := types.FilePath("/workspace/project2")
	org1 := "org-for-project1"
	org2 := "org-for-project2"

	folderConfig1 := &types.FolderConfig{FolderPath: folderPath1, PreferredOrg: org1}
	folderConfig2 := &types.FolderConfig{FolderPath: folderPath2, PreferredOrg: org2}

	// Setup scanner
	productScanner := NewTestProductScanner(product.ProductOpenSource, true)
	scanner, _ := setupScanner(t, c, productScanner)

	// Scan file in folder 1
	scanner.Scan(t.Context(), types.FilePath("/workspace/project1/file1.go"), types.NoopResultProcessor, folderConfig1)
	assert.Eventually(t, func() bool {
		return productScanner.Scans() == 1
	}, 1*time.Second, 10*time.Millisecond)

	// Verify org1 was used
	config1 := productScanner.LastFolderConfig()
	require.NotNil(t, config1)
	assert.Equal(t, org1, config1.PreferredOrg, "First scan should use org1")
	assert.Equal(t, folderPath1, config1.FolderPath, "First scan should use folderPath1")

	// Scan file in folder 2
	scanner.Scan(t.Context(), types.FilePath("/workspace/project2/file2.go"), types.NoopResultProcessor, folderConfig2)
	assert.Eventually(t, func() bool {
		return productScanner.Scans() == 2
	}, 1*time.Second, 10*time.Millisecond)

	// Verify org2 was used
	config2 := productScanner.LastFolderConfig()
	require.NotNil(t, config2)
	assert.Equal(t, org2, config2.PreferredOrg, "Second scan should use org2")
	assert.Equal(t, folderPath2, config2.FolderPath, "Second scan should use folderPath2")

	// Verify history shows both configs were used
	history := productScanner.FolderConfigHistory()
	require.Len(t, history, 2)
	assert.Equal(t, org1, history[0].PreferredOrg)
	assert.Equal(t, org2, history[1].PreferredOrg)
}

func TestScan_FileScan_PathIsSeparateFromFolderPath(t *testing.T) {
	c := testutil.UnitTest(t)

	// Setup folder config
	folderPath := types.FilePath("/workspace/project")
	folderConfig := &types.FolderConfig{FolderPath: folderPath}

	// Setup scanner
	productScanner := NewTestProductScanner(product.ProductOpenSource, true)
	scanner, _ := setupScanner(t, c, productScanner)

	// Scan a specific file (not the folder itself)
	filePath := types.FilePath("/workspace/project/src/deep/nested/file.go")
	scanner.Scan(t.Context(), filePath, types.NoopResultProcessor, folderConfig)

	assert.Eventually(t, func() bool {
		return productScanner.Scans() == 1
	}, 1*time.Second, 10*time.Millisecond)

	// Verify the scanner received both the file path and the folder config
	assert.Equal(t, filePath, productScanner.LastPath(), "path should be the file being scanned")
	assert.Equal(t, folderPath, productScanner.LastFolderConfig().FolderPath, "folderConfig.FolderPath should be the workspace folder")
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
