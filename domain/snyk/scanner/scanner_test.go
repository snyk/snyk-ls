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

	scanner.Scan(t.Context(), "", types.NoopResultProcessor, "")

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
	sc = NewDelegatingScanner(c, initialize.NewDelegatingInitializer(), performance.NewInstrumentor(), scanNotifier, apiClient, authenticationService, notifier, persister, scanStateAggregator, nil, testProductScanners...)
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
	scanner.Scan(t.Context(), "", types.NoopResultProcessor, "")

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
		scanner.Scan(t.Context(), "", types.NoopResultProcessor, "")
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

	sc.Scan(t.Context(), "", types.NoopResultProcessor, "")

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
