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
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"

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
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

func TestScan_UsesEnabledProductLinesOnly(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
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

	scanner, _ := setupScanner(t, engine, tokenService, enabledScanner, disabledScanner)

	fc := &types.FolderConfig{FolderPath: ""}
	ctx := ctx2.NewContextWithFolderConfig(t.Context(), fc)
	scanner.Scan(ctx, "", types.NoopResultProcessor, nil)

	// gomock will verify expectations automatically
}

func setupScanner(t *testing.T, engine workflow.Engine, tokenService types.TokenService, testProductScanners ...types.ProductScanner) (
	sc Scanner,
	scanNotifier ScanNotifier,
) {
	t.Helper()
	resolver := defaultResolver(t, engine)
	return setupScannerWithResolver(t, engine, tokenService, resolver, testProductScanners...)
}

func defaultResolver(t *testing.T, engine workflow.Engine) *types.ConfigResolver {
	t.Helper()
	return testutil.DefaultConfigResolver(engine)
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

func syncFolderToConfig(t *testing.T, engine workflow.Engine, fc *types.FolderConfig, opts *syncFolderOpts) {
	t.Helper()
	conf := engine.GetConfiguration()
	fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
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
		key := configresolver.UserFolderKey(folderPath, name)
		conf.PersistInStorage(key)
		conf.Set(key, &configresolver.LocalConfigField{Value: value, Changed: true})
	}
}

func setupScannerWithResolver(t *testing.T, engine workflow.Engine, tokenService types.TokenService, configResolver types.ConfigResolverInterface, testProductScanners ...types.ProductScanner) (
	sc Scanner,
	scanNotifier ScanNotifier,
) {
	t.Helper()
	return setupScannerWithResolverAndAgg(t, engine, tokenService, configResolver, scanstates.NewNoopStateAggregator(), testProductScanners...)
}

func Test_userNotAuthenticated_ScanSkipped(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	// Arrange
	mockScanner := mock_types.NewMockProductScanner(ctrl)
	mockScanner.EXPECT().Product().Return(product.ProductOpenSource).AnyTimes()
	mockScanner.EXPECT().IsEnabledForFolder(gomock.Any()).Return(true).AnyTimes()
	// Explicitly expect Scan to NOT be called when not authenticated
	mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).Times(0)

	scanner, _ := setupScanner(t, engine, tokenService, mockScanner)
	tokenService.SetToken(engine.GetConfiguration(), "")

	// Act
	fc := &types.FolderConfig{FolderPath: ""}
	ctx := ctx2.NewContextWithFolderConfig(t.Context(), fc)
	scanner.Scan(ctx, "", types.NoopResultProcessor, nil)

	// Assert - gomock will fail if Scan was called
}

func Test_ScanStarted_TokenChanged_ScanCancelled(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	// Arrange - start with a valid token so scan begins
	tokenService.SetToken(engine.GetConfiguration(), uuid.New().String())
	scanStarted := make(chan bool)
	wasCanceled := false

	mockScanner := mock_types.NewMockProductScanner(ctrl)
	mockScanner.EXPECT().Product().Return(product.ProductOpenSource).AnyTimes()
	mockScanner.EXPECT().IsEnabledForFolder(gomock.Any()).Return(true).AnyTimes()
	mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx interface{}, _ types.FilePath) ([]types.Issue, error) {
			scanStarted <- true
			// Block until the scan's context is canceled by the token change.
			// Racing a fixed wall-clock timer here makes the test flaky: under load
			// the cancellation can arrive after the timer, leaving wasCanceled false.
			// The outer RequireEventuallyReceive(done) bounds the wait, so a genuinely
			// broken cancellation surfaces as a "scan should complete" failure instead.
			<-ctx.(interface{ Done() <-chan struct{} }).Done()
			wasCanceled = true
			return []types.Issue{}, nil
		}).Times(1)

	scanner, _ := setupScanner(t, engine, tokenService, mockScanner)
	done := make(chan bool)

	// Act
	go func() {
		fc := &types.FolderConfig{FolderPath: ""}
		ctx := ctx2.NewContextWithFolderConfig(t.Context(), fc)
		scanner.Scan(ctx, "", types.NoopResultProcessor, nil)
		done <- true
	}()

	// Wait for scan to start, then change token to trigger cancellation
	testsupport.RequireEventuallyReceive(t, scanStarted, 5*time.Second, 10*time.Millisecond, "scan should start")
	tokenService.SetToken(engine.GetConfiguration(), uuid.New().String())

	// Wait for scan to complete
	testsupport.RequireEventuallyReceive(t, done, 5*time.Second, 10*time.Millisecond, "scan should complete")

	// Assert - verify the scan was canceled, not timed out
	assert.True(t, wasCanceled, "Scan should have been canceled when token changed")
}

// IDE-1035 (E): Outcome-level test — after user-initiated stop-scan during an
// in-flight scan, the cancel callback registered via RegisterCancelCallback
// must run AFTER all per-product goroutines have finished writing to the
// aggregator, so the final snapshot is the initial (NotStarted) state.
func TestScan_CancelCallback_CalledAfterGoroutinesFinish(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	tokenService.SetToken(engine.GetConfiguration(), uuid.New().String())

	scanStarted := make(chan struct{})

	mockProductScanner := mock_types.NewMockProductScanner(ctrl)
	mockProductScanner.EXPECT().Product().Return(product.ProductOpenSource).AnyTimes()
	mockProductScanner.EXPECT().IsEnabledForFolder(gomock.Any()).Return(true).AnyTimes()
	mockProductScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, _ types.FilePath) ([]types.Issue, error) {
			close(scanStarted)
			// Block until context is canceled (simulates in-flight cancellation).
			<-ctx.Done()
			return []types.Issue{}, nil
		}).Times(1)

	// Track call order to verify SetScanDone precedes the cancel callback.
	type callRecord struct{ kind string }
	var callsMu sync.Mutex
	var calls []callRecord

	agg := &recordingOrderAggregator{
		SetScanDoneFn: func() {
			callsMu.Lock()
			calls = append(calls, callRecord{"SetScanDone"})
			callsMu.Unlock()
		},
	}

	resolver := defaultResolver(t, engine)
	sc, _ := setupScannerWithResolverAndAgg(t, engine, tokenService, resolver, agg, mockProductScanner)

	folderPath := types.FilePath(t.TempDir())
	resetCalled := make(chan struct{}, 1)
	sc.(*DelegatingConcurrentScanner).RegisterCancelCallback(folderPath, func() {
		callsMu.Lock()
		calls = append(calls, callRecord{"Init"})
		callsMu.Unlock()
		resetCalled <- struct{}{}
	})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan struct{})
	go func() {
		fc := &types.FolderConfig{FolderPath: folderPath}
		scanCtx := ctx2.NewContextWithFolderConfig(ctx, fc)
		sc.Scan(scanCtx, folderPath, types.NoopResultProcessor, nil)
		close(done)
	}()

	// Wait for scan to start, then cancel the outer context.
	select {
	case <-scanStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("scan did not start in time")
	}
	cancel()

	// Wait for Scan() to return.
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Scan did not return in time after cancel")
	}

	// The cancel callback must have been called.
	select {
	case <-resetCalled:
	case <-time.After(time.Second):
		t.Fatal("cancel callback was not called after Scan returned")
	}

	// Verify order: SetScanDone must appear before Init.
	callsMu.Lock()
	defer callsMu.Unlock()
	require.GreaterOrEqual(t, len(calls), 2, "expected at least SetScanDone then Init")
	// Find Init call position
	initIdx, setDoneIdx := -1, -1
	for i, c := range calls {
		if c.kind == "SetScanDone" && setDoneIdx == -1 {
			setDoneIdx = i
		}
		if c.kind == "Init" {
			initIdx = i
		}
	}
	require.NotEqual(t, -1, setDoneIdx, "SetScanDone must be called")
	require.NotEqual(t, -1, initIdx, "Init must be called")
	assert.Less(t, setDoneIdx, initIdx, "SetScanDone must be called before Init (no late writes after reset)")
}

// Multi-folder blast-radius regression: a reset callback registered for
// folder A (as if its scan were canceled) must never surface in folder B's
// state. Folder B's own real, successful scan must be reflected as-is.
func TestScan_CancelCallbackForFolderA_DoesNotAffectFolderB(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	tokenService.SetToken(engine.GetConfiguration(), uuid.New().String())

	mockProductScanner := mock_types.NewMockProductScanner(ctrl)
	mockProductScanner.EXPECT().Product().Return(product.ProductOpenSource).AnyTimes()
	mockProductScanner.EXPECT().IsEnabledForFolder(gomock.Any()).Return(true).AnyTimes()
	mockProductScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).Return([]types.Issue{}, nil).Times(1)

	emitter := scanstates.NewMockScanStateChangeEmitter(ctrl)
	emitter.EXPECT().Emit(gomock.Any()).AnyTimes()

	resolver := defaultResolver(t, engine)
	agg := scanstates.NewScanStateAggregator(engine.GetConfiguration(), engine.GetLogger(), emitter, resolver, engine)

	folderA := types.FilePath(t.TempDir())
	folderB := types.FilePath(t.TempDir())
	agg.Init([]types.FilePath{folderA, folderB})

	sc, _ := setupScannerWithResolverAndAgg(t, engine, tokenService, resolver, agg, mockProductScanner)

	// Simulate a stop-scan cancel on folder A: register exactly the reset
	// the LSP cancel handler performs (resetSummaryPanel calls agg.Init).
	sc.(*DelegatingConcurrentScanner).RegisterCancelCallback(folderA, func() {
		agg.Init([]types.FilePath{folderA})
	})

	// Drive a real, successful scan for folder B — unrelated to folder A.
	fc := &types.FolderConfig{FolderPath: folderB}
	ctx := ctx2.NewContextWithFolderConfig(t.Context(), fc)
	sc.Scan(ctx, folderB, types.NoopResultProcessor, nil)

	snapshot := agg.StateSnapshot()
	inProgress, ok := snapshot.ProductScanStates[folderB][product.ProductOpenSource]
	assert.True(t, ok, "folder B's scan result must be recorded, not reset to NotStarted")
	assert.False(t, inProgress, "folder B's scan must show as finished, not reset back to in-progress/not-started")
	assert.Empty(t, snapshot.ProductScanErrors[folderB], "folder B's scan must not show as errored")
}

// recordingOrderAggregator wraps NoopStateAggregator and calls SetScanDoneFn on SetScanDone.
type recordingOrderAggregator struct {
	scanstates.NoopStateAggregator
	SetScanDoneFn func()
}

func (r *recordingOrderAggregator) SetScanDone(fp types.FilePath, p product.Product, ref bool, err error) {
	r.NoopStateAggregator.SetScanDone(fp, p, ref, err)
	if r.SetScanDoneFn != nil {
		r.SetScanDoneFn()
	}
}

func setupScannerWithResolverAndAgg(t *testing.T, engine workflow.Engine, tokenService types.TokenService, configResolver types.ConfigResolverInterface, agg scanstates.Aggregator, testProductScanners ...types.ProductScanner) (
	sc Scanner,
	scanNotifier ScanNotifier,
) {
	t.Helper()
	scanNotifier = NewMockScanNotifier()
	notifier := notification.NewNotifier()
	apiClient := &snyk_api.FakeApiClient{CodeEnabled: false}
	persister := persistence.NewNopScanPersister()
	er := error_reporting.NewTestErrorReporter(engine)
	authenticationProvider := authentication.NewFakeCliAuthenticationProvider(engine)
	authenticationProvider.IsAuthenticated = true
	authenticationService := authentication.NewAuthenticationService(engine, tokenService, authenticationProvider, er, notifier, configResolver)
	sc = NewDelegatingScanner(engine, tokenService, initialize.NewDelegatingInitializer(), performance.NewInstrumentor(), scanNotifier, apiClient, authenticationService, notifier, persister, agg, configResolver, testProductScanners...)
	return sc, scanNotifier
}

func TestScan_whenProductScannerEnabled_SendsInProgress(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	mockScanner := mock_types.NewMockProductScanner(ctrl)
	mockScanner.EXPECT().Product().Return(product.ProductCode).AnyTimes()
	mockScanner.EXPECT().IsEnabledForFolder(gomock.Any()).Return(true).AnyTimes()
	// Expect exactly one scan call
	mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).Return([]types.Issue{}, nil).Times(1)

	sc, scanNotifier := setupScanner(t, engine, tokenService, mockScanner)
	mockScanNotifier := scanNotifier.(*MockScanNotifier)

	fc := &types.FolderConfig{FolderPath: ""}
	ctx := ctx2.NewContextWithFolderConfig(t.Context(), fc)
	sc.Scan(ctx, "", types.NoopResultProcessor, nil)

	// Verify InProgress notification was sent
	assert.NotEmpty(t, mockScanNotifier.InProgressCalls(), "InProgress should be called when scan starts")
}

func TestDelegatingConcurrentScanner_executePreScanCommand(t *testing.T) {
	testsupport.NotOnWindows(t, "/bin/ls does not exist on windows")
	engine, tokenService := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), true)
	p := product.ProductOpenSource
	mockScanner := mock_types.NewMockProductScanner(ctrl)
	mockScanner.EXPECT().Product().Return(p).AnyTimes()
	mockScanner.EXPECT().IsEnabledForFolder(gomock.Any()).Return(true).AnyTimes()

	sc, _ := setupScanner(t, engine, tokenService, mockScanner)
	delegatingScanner, ok := sc.(*DelegatingConcurrentScanner)
	require.True(t, ok)
	workDir := types.FilePath(t.TempDir())

	command := "/bin/sh"

	// setup folder config for prescan
	engineConf := engine.GetConfiguration()
	scanCommandConfigMap := map[product.Product]types.ScanCommandConfig{
		product.ProductOpenSource: {
			PreScanCommand:             command,
			PreScanOnlyReferenceFolder: false,
		},
	}
	fp := string(types.PathKey(workDir))
	engineConf.Set(configresolver.UserFolderKey(fp, types.SettingScanCommandConfig), &configresolver.LocalConfigField{Value: scanCommandConfigMap, Changed: true})
	resolver := testutil.DefaultConfigResolver(engine)
	folderConfig := config.GetFolderConfigFromEngine(engine, resolver, workDir, engine.GetLogger())

	// trigger execute
	err := delegatingScanner.executePreScanCommand(t.Context(), engine, p, folderConfig, workDir, false)
	require.NoError(t, err)
}

func TestScan_FileScan_UsesFolderConfigOrganization(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Setup folder config with specific organization
	folderPath := types.FilePath("/workspace/project")
	expectedOrg := "test-org-123"
	engineConf := engine.GetConfiguration()
	types.SetPreferredOrgAndOrgSetByUser(engineConf, folderPath, expectedOrg, true)
	folderConfig := &types.FolderConfig{FolderPath: folderPath}
	folderConfig.ConfigResolver = types.NewMinimalConfigResolver(engineConf)

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

	scanner, _ := setupScanner(t, engine, tokenService, mockScanner)

	// Scan a single file within the folder
	filePath := types.FilePath("/workspace/project/src/main.go")
	ctx := ctx2.NewContextWithFolderConfig(t.Context(), folderConfig)
	scanner.Scan(ctx, filePath, types.NoopResultProcessor, nil)
}

func TestScan_FileScan_DifferentFoldersUseDifferentOrganizations(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Setup two folder configs with different organizations
	folderPath1 := types.FilePath("/workspace/project1")
	folderPath2 := types.FilePath("/workspace/project2")
	org1 := "org-for-project1"
	org2 := "org-for-project2"

	engineConf := engine.GetConfiguration()
	types.SetPreferredOrgAndOrgSetByUser(engineConf, folderPath1, org1, true)
	types.SetPreferredOrgAndOrgSetByUser(engineConf, folderPath2, org2, true)
	folderConfig1 := &types.FolderConfig{FolderPath: folderPath1}
	folderConfig1.ConfigResolver = types.NewMinimalConfigResolver(engineConf)
	folderConfig2 := &types.FolderConfig{FolderPath: folderPath2}
	folderConfig2.ConfigResolver = types.NewMinimalConfigResolver(engineConf)

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

	scanner, _ := setupScanner(t, engine, tokenService, mockScanner)

	// Scan file in folder 1
	ctx1 := ctx2.NewContextWithFolderConfig(t.Context(), folderConfig1)
	scanner.Scan(ctx1, types.FilePath("/workspace/project1/file1.go"), types.NoopResultProcessor, nil)

	// Scan file in folder 2
	ctx2Val := ctx2.NewContextWithFolderConfig(t.Context(), folderConfig2)
	scanner.Scan(ctx2Val, types.FilePath("/workspace/project2/file2.go"), types.NoopResultProcessor, nil)

	// Verify both configs were received with correct orgs
	require.Len(t, receivedConfigs, 2)
	assert.Equal(t, org1, receivedConfigs[0].PreferredOrg(), "First scan should use org1")
	assert.Equal(t, folderPath1, receivedConfigs[0].FolderPath, "First scan should use folderPath1")
	assert.Equal(t, org2, receivedConfigs[1].PreferredOrg(), "Second scan should use org2")
	assert.Equal(t, folderPath2, receivedConfigs[1].FolderPath, "Second scan should use folderPath2")
}

func TestScan_FileScan_PathIsSeparateFromFolderPath(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
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

	scanner, _ := setupScanner(t, engine, tokenService, mockScanner)

	ctx := ctx2.NewContextWithFolderConfig(t.Context(), folderConfig)
	scanner.Scan(ctx, filePath, types.NoopResultProcessor, nil)
}

// TestEnrichContextAndLogger_InjectsConfigResolver FC-062: DelegatingConcurrentScanner injects ConfigResolver into context
func TestEnrichContextAndLogger_InjectsConfigResolver(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockResolver := mock_types.NewMockConfigResolverInterface(ctrl)
	engine := testutil.UnitTest(t)
	logger := *engine.GetLogger()

	sc := &DelegatingConcurrentScanner{
		engine:         engine,
		configResolver: mockResolver,
	}

	enrichedCtx, _ := sc.enrichContextAndLogger(t.Context(), logger, types.FilePath("/work"), types.FilePath("/work/file.go"))

	resolver, ok := ctx2.ConfigResolverFromContext(enrichedCtx)
	require.True(t, ok)
	require.Same(t, mockResolver, resolver)
}

// FC-102: Full scan pipeline works with ConfigResolver in context; scanners receive folderPath
func Test_FC102_FullScanPipeline_ConfigResolverInContext_ScannersReceiveFolderPath(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockResolver := mock_types.NewMockConfigResolverInterface(ctrl)
	mockResolver.EXPECT().GetEffectiveValue(types.SettingScanCommandConfig, gomock.Any()).Return(types.EffectiveValue{}).AnyTimes()
	mockResolver.EXPECT().IsDeltaFindingsEnabledForFolder(gomock.Any()).Return(false).AnyTimes()
	mockResolver.EXPECT().GetBool(types.SettingOffline, nil).Return(false).AnyTimes()
	mockResolver.EXPECT().GetString(types.SettingDeviceId, nil).Return("").AnyTimes()
	mockResolver.EXPECT().GetValue(types.SettingReferenceFolder, gomock.Any()).Return(nil, configresolver.ConfigSourceDefault).AnyTimes()
	mockResolver.EXPECT().GetValue(types.SettingBaseBranch, gomock.Any()).Return(nil, configresolver.ConfigSourceDefault).AnyTimes()

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

	scanner, _ := setupScannerWithResolver(t, engine, tokenService, mockResolver, mockScanner)
	ctx := ctx2.NewContextWithFolderConfig(t.Context(), folderConfig)
	scanner.Scan(ctx, folderPath, types.NoopResultProcessor, nil)
}

func TestEnrichContextAndLogger_PreservesExistingDeps(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockResolver := mock_types.NewMockConfigResolverInterface(ctrl)
	engine := testutil.UnitTest(t)
	logger := *engine.GetLogger()

	sc := &DelegatingConcurrentScanner{
		engine:         engine,
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

	engine := testutil.UnitTest(t)
	mockResolver := mock_types.NewMockConfigResolverInterface(ctrl)
	mockResolver.EXPECT().GetValue(types.SettingReferenceFolder, gomock.Any()).Return(nil, configresolver.ConfigSourceDefault).AnyTimes()
	mockResolver.EXPECT().GetValue(types.SettingBaseBranch, gomock.Any()).Return(nil, configresolver.ConfigSourceDefault).AnyTimes()

	dcs := &DelegatingConcurrentScanner{
		engine:         engine,
		configResolver: mockResolver,
	}

	engineConf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	folderConfig := &types.FolderConfig{FolderPath: ""}
	folderConfig.ConfigResolver = types.NewMinimalConfigResolver(engineConf)

	// Act
	_, err := dcs.getPersistHash(folderConfig)

	// Assert
	assert.ErrorIs(t, err, ErrMissingDeltaReference)
}
