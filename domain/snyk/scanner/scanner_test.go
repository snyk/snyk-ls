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
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/initialize"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
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
	enabledScanner.EXPECT().IsEnabledForFolder(gomock.Any()).Return(true).AnyTimes()
	enabledScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).Return([]types.Issue{}, nil).Times(1)

	disabledScanner := mock_types.NewMockProductScanner(ctrl)
	disabledScanner.EXPECT().Product().Return(product.ProductOpenSource).AnyTimes()
	disabledScanner.EXPECT().IsEnabledForFolder(gomock.Any()).Return(false).MinTimes(1)
	// Explicitly verify Scan is NOT called on disabled scanner
	disabledScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).Times(0)

	scanner, _ := setupScanner(t, c, enabledScanner, disabledScanner)

	fc := &types.FolderConfig{FolderPath: ""}
	ctx := ctx2.NewContextWithFolderConfig(t.Context(), fc)
	scanner.Scan(ctx, "", types.NoopResultProcessor)

	// gomock will verify expectations automatically
}

func setupScanner(t *testing.T, c *config.Config, testProductScanners ...types.ProductScanner) (
	sc Scanner,
	scanNotifier ScanNotifier,
) {
	t.Helper()
	resolver := defaultResolver(t, c)
	return setupScannerWithResolver(t, c, resolver, testProductScanners...)
}

func defaultResolver(t *testing.T, c *config.Config) *types.ConfigResolver {
	t.Helper()
	return testutil.DefaultConfigResolver(c)
}

// syncFolderOpts holds optional values to write to configuration when syncing a folder config.
type syncFolderOpts struct {
	PreferredOrg         string
	OrgSetByUser         bool
	ReferenceFolderPath  types.FilePath
	BaseBranch           string
	AdditionalParameters []string
	AutoDeterminedOrg    string
	LocalBranches        []string
	UserOverrides        map[string]any
}

func syncFolderToConfig(t *testing.T, c *config.Config, fc *types.FolderConfig, opts *syncFolderOpts) {
	t.Helper()
	conf := c.Engine().GetConfiguration()
	fc.SetConf(conf)
	if conf == nil || fc == nil {
		return
	}
	if opts == nil {
		return
	}
	folderPath := string(types.PathKey(fc.FolderPath))
	types.SetPreferredOrgAndOrgSetByUser(conf, fc.FolderPath, opts.PreferredOrg, opts.OrgSetByUser)
	if opts.BaseBranch != "" {
		types.SetFolderUserSetting(conf, fc.FolderPath, types.SettingBaseBranch, opts.BaseBranch)
		types.SetFolderUserSetting(conf, fc.FolderPath, types.SettingReferenceBranch, opts.BaseBranch)
	}
	if len(opts.AdditionalParameters) > 0 {
		types.SetFolderUserSetting(conf, fc.FolderPath, types.SettingAdditionalParameters, opts.AdditionalParameters)
	}
	if opts.AutoDeterminedOrg != "" {
		types.SetAutoDeterminedOrg(conf, fc.FolderPath, opts.AutoDeterminedOrg)
	}
	if len(opts.LocalBranches) > 0 {
		types.SetFolderMetadataSetting(conf, fc.FolderPath, types.SettingLocalBranches, opts.LocalBranches)
	}
	if opts.ReferenceFolderPath != "" {
		types.SetFolderUserSetting(conf, fc.FolderPath, types.SettingReferenceFolder, string(opts.ReferenceFolderPath))
	}
	for name, value := range opts.UserOverrides {
		key := configuration.UserFolderKey(folderPath, name)
		conf.PersistInStorage(key)
		conf.Set(key, &configuration.LocalConfigField{Value: value, Changed: true})
	}
}

func setupScannerWithResolver(t *testing.T, c *config.Config, configResolver types.ConfigResolverInterface, testProductScanners ...types.ProductScanner) (
	sc Scanner,
	scanNotifier ScanNotifier,
) {
	t.Helper()
	scanNotifier = NewMockScanNotifier()
	notifier := notification.NewNotifier()
	apiClient := &snyk_api.FakeApiClient{CodeEnabled: false}
	persister := persistence.NewNopScanPersister()
	scanStateAggregator := scanstates.NewNoopStateAggregator()
	er := error_reporting.NewTestErrorReporter(c)
	authenticationProvider := authentication.NewFakeCliAuthenticationProvider(c)
	authenticationProvider.IsAuthenticated = true
	authenticationService := authentication.NewAuthenticationService(c, authenticationProvider, er, notifier)
	sc = NewDelegatingScanner(c, initialize.NewDelegatingInitializer(), performance.NewInstrumentor(), scanNotifier, apiClient, authenticationService, notifier, persister, scanStateAggregator, configResolver, testProductScanners...)
	return sc, scanNotifier
}

func Test_userNotAuthenticated_ScanSkipped(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	// Arrange
	mockScanner := mock_types.NewMockProductScanner(ctrl)
	mockScanner.EXPECT().Product().Return(product.ProductOpenSource).AnyTimes()
	mockScanner.EXPECT().IsEnabledForFolder(gomock.Any()).Return(true).AnyTimes()
	// Explicitly expect Scan to NOT be called when not authenticated
	mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).Times(0)

	scanner, _ := setupScanner(t, c, mockScanner)
	c.SetToken("")

	// Act
	fc := &types.FolderConfig{FolderPath: ""}
	ctx := ctx2.NewContextWithFolderConfig(t.Context(), fc)
	scanner.Scan(ctx, "", types.NoopResultProcessor)

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
	mockScanner.EXPECT().IsEnabledForFolder(gomock.Any()).Return(true).AnyTimes()
	mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx interface{}, _ types.FilePath) ([]types.Issue, error) {
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
		fc := &types.FolderConfig{FolderPath: ""}
		ctx := ctx2.NewContextWithFolderConfig(t.Context(), fc)
		scanner.Scan(ctx, "", types.NoopResultProcessor)
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

	c.Engine().GetConfiguration().Set(configuration.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	mockScanner := mock_types.NewMockProductScanner(ctrl)
	mockScanner.EXPECT().Product().Return(product.ProductCode).AnyTimes()
	mockScanner.EXPECT().IsEnabledForFolder(gomock.Any()).Return(true).AnyTimes()
	// Expect exactly one scan call
	mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).Return([]types.Issue{}, nil).Times(1)

	sc, scanNotifier := setupScanner(t, c, mockScanner)
	mockScanNotifier := scanNotifier.(*MockScanNotifier)

	fc := &types.FolderConfig{FolderPath: ""}
	ctx := ctx2.NewContextWithFolderConfig(t.Context(), fc)
	sc.Scan(ctx, "", types.NoopResultProcessor)

	// Verify InProgress notification was sent
	assert.NotEmpty(t, mockScanNotifier.InProgressCalls(), "InProgress should be called when scan starts")
}

func TestDelegatingConcurrentScanner_executePreScanCommand(t *testing.T) {
	testsupport.NotOnWindows(t, "/bin/ls does not exist on windows")
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	c.Engine().GetConfiguration().Set(configuration.UserGlobalKey(types.SettingSnykOssEnabled), true)
	p := product.ProductOpenSource
	mockScanner := mock_types.NewMockProductScanner(ctrl)
	mockScanner.EXPECT().Product().Return(p).AnyTimes()
	mockScanner.EXPECT().IsEnabledForFolder(gomock.Any()).Return(true).AnyTimes()

	sc, _ := setupScanner(t, c, mockScanner)
	delegatingScanner, ok := sc.(*DelegatingConcurrentScanner)
	require.True(t, ok)
	workDir := types.FilePath(t.TempDir())

	command := "/bin/sh"

	// setup folder config for prescan
	engineConf := c.Engine().GetConfiguration()
	scanCommandConfigMap := map[product.Product]types.ScanCommandConfig{
		product.ProductOpenSource: {
			PreScanCommand:             command,
			PreScanOnlyReferenceFolder: false,
		},
	}
	fp := string(types.PathKey(workDir))
	engineConf.Set(configuration.UserFolderKey(fp, types.SettingScanCommandConfig), &configuration.LocalConfigField{Value: scanCommandConfigMap, Changed: true})
	folderConfig := config.GetFolderConfigFromEngine(c.Engine(), c.GetConfigResolver(), workDir, c.Logger())
	require.NoError(t, storedconfig.UpdateFolderConfig(engineConf, folderConfig, c.Logger()))

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
	engineConf := c.Engine().GetConfiguration()
	types.SetPreferredOrgAndOrgSetByUser(engineConf, folderPath, expectedOrg, true)
	folderConfig := &types.FolderConfig{FolderPath: folderPath}
	folderConfig.SetConf(engineConf)

	// Setup mock scanner that verifies the folderConfig
	mockScanner := mock_types.NewMockProductScanner(ctrl)
	mockScanner.EXPECT().Product().Return(product.ProductOpenSource).AnyTimes()
	mockScanner.EXPECT().IsEnabledForFolder(gomock.Any()).Return(true).AnyTimes()
	mockScanner.EXPECT().Scan(
		gomock.Any(),
		gomock.Any(),
	).DoAndReturn(func(ctx interface{}, _ types.FilePath) ([]types.Issue, error) {
		cfg, ok := ctx2.FolderConfigFromContext(ctx.(context.Context))
		require.True(t, ok, "folderConfig should be in context")
		// Verify the product scanner received the correct folderConfig
		require.NotNil(t, cfg, "folderConfig should be passed to product scanner")
		assert.Equal(t, folderPath, cfg.FolderPath, "folderConfig.FolderPath should match")
		assert.Equal(t, expectedOrg, cfg.PreferredOrg(), "folderConfig organization should match")
		return []types.Issue{}, nil
	}).Times(1)

	scanner, _ := setupScanner(t, c, mockScanner)

	// Scan a single file within the folder
	filePath := types.FilePath("/workspace/project/src/main.go")
	ctx := ctx2.NewContextWithFolderConfig(t.Context(), folderConfig)
	scanner.Scan(ctx, filePath, types.NoopResultProcessor)
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

	engineConf := c.Engine().GetConfiguration()
	types.SetPreferredOrgAndOrgSetByUser(engineConf, folderPath1, org1, true)
	types.SetPreferredOrgAndOrgSetByUser(engineConf, folderPath2, org2, true)
	folderConfig1 := &types.FolderConfig{FolderPath: folderPath1}
	folderConfig1.SetConf(engineConf)
	folderConfig2 := &types.FolderConfig{FolderPath: folderPath2}
	folderConfig2.SetConf(engineConf)

	// Track received configs
	var receivedConfigs []*types.FolderConfig

	// Setup mock scanner
	mockScanner := mock_types.NewMockProductScanner(ctrl)
	mockScanner.EXPECT().Product().Return(product.ProductOpenSource).AnyTimes()
	mockScanner.EXPECT().IsEnabledForFolder(gomock.Any()).Return(true).AnyTimes()
	mockScanner.EXPECT().Scan(
		gomock.Any(),
		gomock.Any(),
	).DoAndReturn(func(ctx interface{}, _ types.FilePath) ([]types.Issue, error) {
		cfg, _ := ctx2.FolderConfigFromContext(ctx.(context.Context))
		receivedConfigs = append(receivedConfigs, cfg)
		return []types.Issue{}, nil
	}).Times(2)

	scanner, _ := setupScanner(t, c, mockScanner)

	// Scan file in folder 1
	ctx1 := ctx2.NewContextWithFolderConfig(t.Context(), folderConfig1)
	scanner.Scan(ctx1, types.FilePath("/workspace/project1/file1.go"), types.NoopResultProcessor)

	// Scan file in folder 2
	ctx2Val := ctx2.NewContextWithFolderConfig(t.Context(), folderConfig2)
	scanner.Scan(ctx2Val, types.FilePath("/workspace/project2/file2.go"), types.NoopResultProcessor)

	// Verify both configs were received with correct orgs
	require.Len(t, receivedConfigs, 2)
	assert.Equal(t, org1, receivedConfigs[0].PreferredOrg(), "First scan should use org1")
	assert.Equal(t, folderPath1, receivedConfigs[0].FolderPath, "First scan should use folderPath1")
	assert.Equal(t, org2, receivedConfigs[1].PreferredOrg(), "Second scan should use org2")
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
	mockScanner.EXPECT().IsEnabledForFolder(gomock.Any()).Return(true).AnyTimes()
	mockScanner.EXPECT().Scan(
		gomock.Any(),
		filePath,
	).DoAndReturn(func(ctx interface{}, path types.FilePath) ([]types.Issue, error) {
		assert.Equal(t, filePath, path, "path should be the file being scanned")
		cfg, ok := ctx2.FolderConfigFromContext(ctx.(context.Context))
		require.True(t, ok, "folderConfig should be in context")
		assert.Equal(t, folderPath, cfg.FolderPath, "folderConfig.FolderPath should be the workspace folder")
		return []types.Issue{}, nil
	}).Times(1)

	scanner, _ := setupScanner(t, c, mockScanner)

	ctx := ctx2.NewContextWithFolderConfig(t.Context(), folderConfig)
	scanner.Scan(ctx, filePath, types.NoopResultProcessor)
}

// TestEnrichContextAndLogger_InjectsConfigResolver FC-062: DelegatingConcurrentScanner injects ConfigResolver into context
func TestEnrichContextAndLogger_InjectsConfigResolver(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockResolver := mock_types.NewMockConfigResolverInterface(ctrl)
	c := testutil.UnitTest(t)
	logger := *c.Logger()

	sc := &DelegatingConcurrentScanner{
		c:              c,
		configResolver: mockResolver,
	}

	enrichedCtx, _ := sc.enrichContextAndLogger(t.Context(), logger, types.FilePath("/work"), types.FilePath("/work/file.go"))

	resolver, ok := ctx2.ConfigResolverFromContext(enrichedCtx)
	require.True(t, ok)
	require.Same(t, mockResolver, resolver)
}

// FC-102: Full scan pipeline works with ConfigResolver in context; scanners receive folderPath
func Test_FC102_FullScanPipeline_ConfigResolverInContext_ScannersReceiveFolderPath(t *testing.T) {
	c := testutil.UnitTest(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockResolver := mock_types.NewMockConfigResolverInterface(ctrl)
	// Resolver is used during pre-scan and delta resolution
	mockResolver.EXPECT().GetEffectiveValue(types.SettingScanCommandConfig, gomock.Any()).Return(types.EffectiveValue{}).AnyTimes()
	mockResolver.EXPECT().IsDeltaFindingsEnabledForFolder(gomock.Any()).Return(false).AnyTimes()

	folderPath := types.FilePath("/workspace/project")
	folderConfig := &types.FolderConfig{FolderPath: folderPath}

	mockScanner := mock_types.NewMockProductScanner(ctrl)
	mockScanner.EXPECT().Product().Return(product.ProductOpenSource).AnyTimes()
	mockScanner.EXPECT().IsEnabledForFolder(gomock.Any()).Return(true).AnyTimes()
	mockScanner.EXPECT().Scan(
		gomock.Any(),
		folderPath,
	).DoAndReturn(func(ctx context.Context, path types.FilePath) ([]types.Issue, error) {
		resolver, ok := ctx2.ConfigResolverFromContext(ctx)
		require.True(t, ok, "ConfigResolver should be in context during scan")
		require.NotNil(t, resolver, "ConfigResolver should be non-nil")
		assert.Equal(t, folderPath, path, "scanner should receive folder path as pathToScan")
		cfg, ok := ctx2.FolderConfigFromContext(ctx)
		require.True(t, ok, "folderConfig should be in context")
		require.NotNil(t, cfg, "folderConfig should be passed to scanner")
		assert.Equal(t, folderPath, cfg.FolderPath, "scanner should receive folderConfig with correct FolderPath")
		return []types.Issue{}, nil
	}).Times(1)

	scanner, _ := setupScannerWithResolver(t, c, mockResolver, mockScanner)
	ctx := ctx2.NewContextWithFolderConfig(t.Context(), folderConfig)
	scanner.Scan(ctx, folderPath, types.NoopResultProcessor)
}

func TestEnrichContextAndLogger_PreservesExistingDeps(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockResolver := mock_types.NewMockConfigResolverInterface(ctrl)
	c := testutil.UnitTest(t)
	logger := *c.Logger()

	sc := &DelegatingConcurrentScanner{
		c:              c,
		configResolver: mockResolver,
	}

	folderConfig := &types.FolderConfig{FolderPath: "/test/path"}
	ctx := ctx2.NewContextWithFolderConfig(t.Context(), folderConfig)

	enrichedCtx, _ := sc.enrichContextAndLogger(ctx, logger, types.FilePath("/work"), types.FilePath("/work/file.go"))

	fc, ok := ctx2.FolderConfigFromContext(enrichedCtx)
	require.True(t, ok, "FolderConfig should be preserved from incoming context")
	require.Same(t, folderConfig, fc, "FolderConfig should be the same instance")
}

func TestDelegatingConcurrentScanner_getPersistHash_ErrorOnMissingReference(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	c := testutil.UnitTest(t)
	mockResolver := mock_types.NewMockConfigResolverInterface(ctrl)
	mockResolver.EXPECT().GetValue(types.SettingReferenceFolder, gomock.Any()).Return(nil, types.ConfigSourceDefault).AnyTimes()
	mockResolver.EXPECT().GetValue(types.SettingBaseBranch, gomock.Any()).Return(nil, types.ConfigSourceDefault).AnyTimes()

	dcs := &DelegatingConcurrentScanner{
		c:              c,
		configResolver: mockResolver,
	}

	engineConf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	folderConfig := &types.FolderConfig{FolderPath: ""}
	folderConfig.SetConf(engineConf)

	// Act
	_, err := dcs.getPersistHash(folderConfig)

	// Assert
	assert.ErrorIs(t, err, ErrMissingDeltaReference)
}
