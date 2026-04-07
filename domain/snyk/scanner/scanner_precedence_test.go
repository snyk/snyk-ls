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
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

// newTestConfigResolver creates a real ConfigResolver with configuration resolver for integration testing.
// Callers write global settings directly to conf via conf.Set(configresolver.UserGlobalKey(types.SettingXxx), value).
func newTestConfigResolver(t *testing.T) (*types.ConfigResolver, configuration.Configuration) {
	t.Helper()
	conf := configuration.NewWithOpts()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	require.NoError(t, conf.AddFlagSet(fs))
	fm := workflow.ConfigurationOptionsFromFlagset(fs)
	prefixKeyResolver := configresolver.New(conf, fm)
	logger := zerolog.Nop()
	resolver := types.NewConfigResolver(&logger)
	resolver.SetPrefixKeyResolver(prefixKeyResolver, conf, fm)
	return resolver, conf
}

// newMockScannerWithRealEnablement creates a mock ProductScanner whose IsEnabledForFolder
// delegates to the real ConfigResolver.IsProductEnabledForFolder chain, ensuring the full
// ConfigResolver precedence is exercised during scan decisions.
func newMockScannerWithRealEnablement(
	ctrl *gomock.Controller,
	_ workflow.Engine,
	p product.Product,
	resolver types.ConfigResolverInterface,
) *mock_types.MockProductScanner {
	mockScanner := mock_types.NewMockProductScanner(ctrl)
	mockScanner.EXPECT().Product().Return(p).AnyTimes()
	mockScanner.EXPECT().IsEnabledForFolder(gomock.Any()).DoAndReturn(func(fc *types.FolderConfig) bool {
		return resolver.IsProductEnabledForFolder(p, fc)
	}).AnyTimes()
	return mockScanner
}

// --- A. Product Enablement Precedence → Scan Runs/Skips ---

func TestScanPrecedence_DefaultFallback_ProductDisabled_ScanSkipped(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), false)
	resolver, _ := newTestConfigResolver(t)

	mockScanner := newMockScannerWithRealEnablement(ctrl, engine, product.ProductCode, resolver)
	mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).Times(0)

	sc, _ := setupScannerWithResolver(t, engine, tokenService, resolver, mockScanner)
	folderPath := types.FilePath(t.TempDir())
	ctx := ctx2.NewContextWithFolderConfig(t.Context(), &types.FolderConfig{FolderPath: folderPath})
	sc.Scan(ctx, folderPath, types.NoopResultProcessor, nil)
}

func TestScanPrecedence_GlobalEnablesProduct_ScanRuns(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	resolver, conf := newTestConfigResolver(t)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)

	mockScanner := newMockScannerWithRealEnablement(ctrl, engine, product.ProductCode, resolver)
	mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).Return([]types.Issue{}, nil).Times(1)

	sc, _ := setupScannerWithResolver(t, engine, tokenService, resolver, mockScanner)
	folderPath := types.FilePath(t.TempDir())
	ctx := ctx2.NewContextWithFolderConfig(t.Context(), &types.FolderConfig{FolderPath: folderPath})
	sc.Scan(ctx, folderPath, types.NoopResultProcessor, nil)
}

func TestScanPrecedence_LDXSyncEnablesProduct_NoGlobal_ScanRuns(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), false)

	orgConfig := types.NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(types.SettingSnykCodeEnabled, true, false, "org")

	resolver, conf := newTestConfigResolver(t)
	types.WriteOrgConfigToConfiguration(conf, orgConfig)

	mockScanner := newMockScannerWithRealEnablement(ctrl, engine, product.ProductCode, resolver)
	mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).Return([]types.Issue{}, nil).Times(1)

	sc, _ := setupScannerWithResolver(t, engine, tokenService, resolver, mockScanner)
	folderPath := types.FilePath(t.TempDir())
	fc := &types.FolderConfig{FolderPath: folderPath}
	fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
	fp := string(types.PathKey(fc.FolderPath))
	conf.Set(configresolver.UserFolderKey(fp, types.SettingPreferredOrg), &configresolver.LocalConfigField{Value: "org1", Changed: true})
	conf.Set(configresolver.UserFolderKey(fp, types.SettingOrgSetByUser), &configresolver.LocalConfigField{Value: true, Changed: true})
	ctx := ctx2.NewContextWithFolderConfig(t.Context(), fc)
	sc.Scan(ctx, folderPath, types.NoopResultProcessor, nil)
}

func TestScanPrecedence_GlobalDisablesProduct_OverridesLDXSync_ScanSkipped(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), false)

	orgConfig := types.NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(types.SettingSnykCodeEnabled, true, false, "org")

	resolver, conf := newTestConfigResolver(t)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), false)
	types.WriteOrgConfigToConfiguration(conf, orgConfig)

	mockScanner := newMockScannerWithRealEnablement(ctrl, engine, product.ProductCode, resolver)
	mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).Times(0)

	sc, _ := setupScannerWithResolver(t, engine, tokenService, resolver, mockScanner)
	folderPath := types.FilePath(t.TempDir())
	fc := &types.FolderConfig{FolderPath: folderPath}
	fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
	fp := string(types.PathKey(fc.FolderPath))
	conf.Set(configresolver.UserFolderKey(fp, types.SettingPreferredOrg), &configresolver.LocalConfigField{Value: "org1", Changed: true})
	conf.Set(configresolver.UserFolderKey(fp, types.SettingOrgSetByUser), &configresolver.LocalConfigField{Value: true, Changed: true})
	ctx := ctx2.NewContextWithFolderConfig(t.Context(), fc)
	sc.Scan(ctx, folderPath, types.NoopResultProcessor, nil)
}

func TestScanPrecedence_UserFolderOverrideEnablesProduct_OverGlobalDisabled_ScanRuns(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), false)
	resolver, conf := newTestConfigResolver(t)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), false)

	mockScanner := newMockScannerWithRealEnablement(ctrl, engine, product.ProductCode, resolver)
	mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).Return([]types.Issue{}, nil).Times(1)

	sc, _ := setupScannerWithResolver(t, engine, tokenService, resolver, mockScanner)
	folderPath := types.FilePath(t.TempDir())
	fc := &types.FolderConfig{FolderPath: folderPath}
	fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
	fp := string(types.PathKey(fc.FolderPath))
	conf.Set(configresolver.UserFolderKey(fp, types.SettingSnykCodeEnabled), &configresolver.LocalConfigField{Value: true, Changed: true})
	ctx := ctx2.NewContextWithFolderConfig(t.Context(), fc)
	sc.Scan(ctx, folderPath, types.NoopResultProcessor, nil)
}

func TestScanPrecedence_LDXSyncLockedDisables_OverridesUserOverride_ScanSkipped(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)

	orgConfig := types.NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(types.SettingSnykCodeEnabled, false, true, "group")

	resolver, conf := newTestConfigResolver(t)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	types.WriteOrgConfigToConfiguration(conf, orgConfig)

	mockScanner := newMockScannerWithRealEnablement(ctrl, engine, product.ProductCode, resolver)
	mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).Times(0)

	sc, _ := setupScannerWithResolver(t, engine, tokenService, resolver, mockScanner)
	folderPath := types.FilePath(t.TempDir())
	fc := &types.FolderConfig{FolderPath: folderPath}
	fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
	fp := string(types.PathKey(fc.FolderPath))
	conf.Set(configresolver.UserFolderKey(fp, types.SettingPreferredOrg), &configresolver.LocalConfigField{Value: "org1", Changed: true})
	conf.Set(configresolver.UserFolderKey(fp, types.SettingOrgSetByUser), &configresolver.LocalConfigField{Value: true, Changed: true})
	conf.Set(configresolver.UserFolderKey(fp, types.SettingSnykCodeEnabled), &configresolver.LocalConfigField{Value: true, Changed: true})
	ctx := ctx2.NewContextWithFolderConfig(t.Context(), fc)
	sc.Scan(ctx, folderPath, types.NoopResultProcessor, nil)
}

func TestScanPrecedence_LDXSyncLockedEnables_OverridesUserOverrideFalse_ScanRuns(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), false)

	orgConfig := types.NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(types.SettingSnykCodeEnabled, true, true, "group")

	resolver, conf := newTestConfigResolver(t)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), false)
	types.WriteOrgConfigToConfiguration(conf, orgConfig)

	mockScanner := newMockScannerWithRealEnablement(ctrl, engine, product.ProductCode, resolver)
	mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).Return([]types.Issue{}, nil).Times(1)

	sc, _ := setupScannerWithResolver(t, engine, tokenService, resolver, mockScanner)
	folderPath := types.FilePath(t.TempDir())
	fc := &types.FolderConfig{FolderPath: folderPath}
	fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
	fp := string(types.PathKey(fc.FolderPath))
	conf.Set(configresolver.UserFolderKey(fp, types.SettingPreferredOrg), &configresolver.LocalConfigField{Value: "org1", Changed: true})
	conf.Set(configresolver.UserFolderKey(fp, types.SettingOrgSetByUser), &configresolver.LocalConfigField{Value: true, Changed: true})
	conf.Set(configresolver.UserFolderKey(fp, types.SettingSnykCodeEnabled), &configresolver.LocalConfigField{Value: false, Changed: true})
	ctx := ctx2.NewContextWithFolderConfig(t.Context(), fc)
	sc.Scan(ctx, folderPath, types.NoopResultProcessor, nil)
}

// --- B. Multi-Folder Precedence → Different Behavior Per Folder ---

func TestScanPrecedence_MultiFolderDifferentOrgs_DifferentScanBehavior(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), false)

	org1Config := types.NewLDXSyncOrgConfig("org-enabled")
	org1Config.SetField(types.SettingSnykCodeEnabled, true, true, "group")

	org2Config := types.NewLDXSyncOrgConfig("org-disabled")
	org2Config.SetField(types.SettingSnykCodeEnabled, false, true, "group")

	resolver, conf := newTestConfigResolver(t)
	types.WriteOrgConfigToConfiguration(conf, org1Config)
	types.WriteOrgConfigToConfiguration(conf, org2Config)

	scanCount := 0
	mockScanner := newMockScannerWithRealEnablement(ctrl, engine, product.ProductCode, resolver)
	mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, _ types.FilePath) ([]types.Issue, error) {
			scanCount++
			return []types.Issue{}, nil
		},
	).AnyTimes()

	sc, _ := setupScannerWithResolver(t, engine, tokenService, resolver, mockScanner)

	folder1 := types.FilePath(t.TempDir())
	fc1 := &types.FolderConfig{FolderPath: folder1}
	fc1.ConfigResolver = types.NewMinimalConfigResolver(conf)
	fp1 := string(types.PathKey(fc1.FolderPath))
	conf.Set(configresolver.UserFolderKey(fp1, types.SettingPreferredOrg), &configresolver.LocalConfigField{Value: "org-enabled", Changed: true})
	conf.Set(configresolver.UserFolderKey(fp1, types.SettingOrgSetByUser), &configresolver.LocalConfigField{Value: true, Changed: true})

	folder2 := types.FilePath(t.TempDir())
	fc2 := &types.FolderConfig{FolderPath: folder2}
	fc2.ConfigResolver = types.NewMinimalConfigResolver(conf)
	fp2 := string(types.PathKey(fc2.FolderPath))
	conf.Set(configresolver.UserFolderKey(fp2, types.SettingPreferredOrg), &configresolver.LocalConfigField{Value: "org-disabled", Changed: true})
	conf.Set(configresolver.UserFolderKey(fp2, types.SettingOrgSetByUser), &configresolver.LocalConfigField{Value: true, Changed: true})

	ctx1 := ctx2.NewContextWithFolderConfig(t.Context(), fc1)
	ct2 := ctx2.NewContextWithFolderConfig(t.Context(), fc2)
	sc.Scan(ctx1, folder1, types.NoopResultProcessor, nil)
	sc.Scan(ct2, folder2, types.NoopResultProcessor, nil)

	assert.Equal(t, 1, scanCount, "only the folder with enabled org should have been scanned")
}

func TestScanPrecedence_MultiFolderDifferentOverrides_CorrectPerFolderBehavior(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), false)
	resolver, conf := newTestConfigResolver(t)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), false)

	var scannedFolders []types.FilePath
	mockScanner := newMockScannerWithRealEnablement(ctrl, engine, product.ProductOpenSource, resolver)
	mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, _ types.FilePath) ([]types.Issue, error) {
			cfg, _ := ctx2.FolderConfigFromContext(ctx)
			scannedFolders = append(scannedFolders, cfg.FolderPath)
			return []types.Issue{}, nil
		},
	).AnyTimes()

	sc, _ := setupScannerWithResolver(t, engine, tokenService, resolver, mockScanner)

	folder1 := types.FilePath(t.TempDir())
	fc1 := &types.FolderConfig{FolderPath: folder1}
	fc1.ConfigResolver = types.NewMinimalConfigResolver(conf)
	fp1 := string(types.PathKey(fc1.FolderPath))
	conf.Set(configresolver.UserFolderKey(fp1, types.SettingSnykOssEnabled), &configresolver.LocalConfigField{Value: true, Changed: true})

	folder2 := types.FilePath(t.TempDir())
	fc2 := &types.FolderConfig{FolderPath: folder2}
	fc2.ConfigResolver = types.NewMinimalConfigResolver(conf)

	folder3 := types.FilePath(t.TempDir())
	fc3 := &types.FolderConfig{FolderPath: folder3}
	fc3.ConfigResolver = types.NewMinimalConfigResolver(conf)
	conf.Set(configresolver.UserFolderKey(string(types.PathKey(folder3)), types.SettingSnykOssEnabled), &configresolver.LocalConfigField{Value: true, Changed: true})

	ctx1 := ctx2.NewContextWithFolderConfig(t.Context(), fc1)
	ctxForFolder2 := ctx2.NewContextWithFolderConfig(t.Context(), fc2)
	ctx3 := ctx2.NewContextWithFolderConfig(t.Context(), fc3)
	sc.Scan(ctx1, folder1, types.NoopResultProcessor, nil)
	sc.Scan(ctxForFolder2, folder2, types.NoopResultProcessor, nil)
	sc.Scan(ctx3, folder3, types.NoopResultProcessor, nil)

	assert.Len(t, scannedFolders, 2, "only folders with user override=true should be scanned")
	assert.Contains(t, scannedFolders, folder1)
	assert.Contains(t, scannedFolders, folder3)
}

// --- C. All Products × All Precedence Levels ---

func TestScanPrecedence_AllProducts_GlobalEnabled_ScanRuns(t *testing.T) {
	products := []struct {
		p       product.Product
		setting string
	}{
		{product.ProductCode, "ActivateSnykCode"},
		{product.ProductOpenSource, "ActivateSnykOpenSource"},
		{product.ProductInfrastructureAsCode, "ActivateSnykIac"},
	}

	for _, tc := range products {
		t.Run(string(tc.p), func(t *testing.T) {
			engine, tokenService := testutil.UnitTestWithEngine(t)
			ctrl := gomock.NewController(t)
			t.Cleanup(ctrl.Finish)

			enableProduct(engine, tc.p, true)
			resolver, conf := newTestConfigResolver(t)
			setProductEnabledInConf(conf, tc.p, true)

			mockScanner := newMockScannerWithRealEnablement(ctrl, engine, tc.p, resolver)
			mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).Return([]types.Issue{}, nil).Times(1)

			sc, _ := setupScannerWithResolver(t, engine, tokenService, resolver, mockScanner)
			folderPath := types.FilePath(t.TempDir())
			ctx := ctx2.NewContextWithFolderConfig(t.Context(), &types.FolderConfig{FolderPath: folderPath})
			sc.Scan(ctx, folderPath, types.NoopResultProcessor, nil)
		})
	}
}

func TestScanPrecedence_AllProducts_GlobalDisabled_ScanSkipped(t *testing.T) {
	products := []struct {
		p       product.Product
		setting string
	}{
		{product.ProductCode, "ActivateSnykCode"},
		{product.ProductOpenSource, "ActivateSnykOpenSource"},
		{product.ProductInfrastructureAsCode, "ActivateSnykIac"},
	}

	for _, tc := range products {
		t.Run(string(tc.p), func(t *testing.T) {
			engine, tokenService := testutil.UnitTestWithEngine(t)
			ctrl := gomock.NewController(t)
			t.Cleanup(ctrl.Finish)

			enableProduct(engine, tc.p, false)
			resolver, conf := newTestConfigResolver(t)
			setProductEnabledInConf(conf, tc.p, false)

			mockScanner := newMockScannerWithRealEnablement(ctrl, engine, tc.p, resolver)
			mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).Times(0)

			sc, _ := setupScannerWithResolver(t, engine, tokenService, resolver, mockScanner)
			folderPath := types.FilePath(t.TempDir())
			ctx := ctx2.NewContextWithFolderConfig(t.Context(), &types.FolderConfig{FolderPath: folderPath})
			sc.Scan(ctx, folderPath, types.NoopResultProcessor, nil)
		})
	}
}

func TestScanPrecedence_AllProducts_LockedLDXSync_OverridesAll(t *testing.T) {
	productSettings := []struct {
		p       product.Product
		setting string
	}{
		{product.ProductCode, types.SettingSnykCodeEnabled},
		{product.ProductOpenSource, types.SettingSnykOssEnabled},
		{product.ProductInfrastructureAsCode, types.SettingSnykIacEnabled},
	}

	for _, tc := range productSettings {
		t.Run(string(tc.p)+"_locked_true_overrides_global_false", func(t *testing.T) {
			engine, tokenService := testutil.UnitTestWithEngine(t)
			ctrl := gomock.NewController(t)
			t.Cleanup(ctrl.Finish)

			enableProduct(engine, tc.p, false)

			orgConfig := types.NewLDXSyncOrgConfig("org1")
			orgConfig.SetField(tc.setting, true, true, "group")

			resolver, conf := newTestConfigResolver(t)
			setProductEnabledInConf(conf, tc.p, false)
			types.WriteOrgConfigToConfiguration(conf, orgConfig)

			mockScanner := newMockScannerWithRealEnablement(ctrl, engine, tc.p, resolver)
			mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).Return([]types.Issue{}, nil).Times(1)

			sc, _ := setupScannerWithResolver(t, engine, tokenService, resolver, mockScanner)
			folderPath := types.FilePath(t.TempDir())
			fc := &types.FolderConfig{FolderPath: folderPath}
			fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
			fp := string(types.PathKey(fc.FolderPath))
			conf.Set(configresolver.UserFolderKey(fp, types.SettingPreferredOrg), &configresolver.LocalConfigField{Value: "org1", Changed: true})
			conf.Set(configresolver.UserFolderKey(fp, types.SettingOrgSetByUser), &configresolver.LocalConfigField{Value: true, Changed: true})
			ctx := ctx2.NewContextWithFolderConfig(t.Context(), fc)
			sc.Scan(ctx, folderPath, types.NoopResultProcessor, nil)
		})

		t.Run(string(tc.p)+"_locked_false_overrides_user_override_true", func(t *testing.T) {
			engine, tokenService := testutil.UnitTestWithEngine(t)
			ctrl := gomock.NewController(t)
			t.Cleanup(ctrl.Finish)

			enableProduct(engine, tc.p, true)

			orgConfig := types.NewLDXSyncOrgConfig("org1")
			orgConfig.SetField(tc.setting, false, true, "group")

			resolver, conf := newTestConfigResolver(t)
			setProductEnabledInConf(conf, tc.p, true)
			types.WriteOrgConfigToConfiguration(conf, orgConfig)

			mockScanner := newMockScannerWithRealEnablement(ctrl, engine, tc.p, resolver)
			mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).Times(0)

			sc, _ := setupScannerWithResolver(t, engine, tokenService, resolver, mockScanner)
			folderPath := types.FilePath(t.TempDir())
			fc := &types.FolderConfig{FolderPath: folderPath}
			fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
			fp := string(types.PathKey(fc.FolderPath))
			conf.Set(configresolver.UserFolderKey(fp, types.SettingPreferredOrg), &configresolver.LocalConfigField{Value: "org1", Changed: true})
			conf.Set(configresolver.UserFolderKey(fp, types.SettingOrgSetByUser), &configresolver.LocalConfigField{Value: true, Changed: true})
			conf.Set(configresolver.UserFolderKey(fp, tc.setting), &configresolver.LocalConfigField{Value: true, Changed: true})
			ctx := ctx2.NewContextWithFolderConfig(t.Context(), fc)
			sc.Scan(ctx, folderPath, types.NoopResultProcessor, nil)
		})
	}
}

func TestScanPrecedence_AllProducts_UserOverride_OverridesGlobal(t *testing.T) {
	productSettings := []struct {
		p       product.Product
		setting string
	}{
		{product.ProductCode, types.SettingSnykCodeEnabled},
		{product.ProductOpenSource, types.SettingSnykOssEnabled},
		{product.ProductInfrastructureAsCode, types.SettingSnykIacEnabled},
	}

	for _, tc := range productSettings {
		t.Run(string(tc.p)+"_override_true_over_global_false", func(t *testing.T) {
			engine, tokenService := testutil.UnitTestWithEngine(t)
			ctrl := gomock.NewController(t)
			t.Cleanup(ctrl.Finish)

			enableProduct(engine, tc.p, false)
			resolver, conf := newTestConfigResolver(t)
			setProductEnabledInConf(conf, tc.p, false)

			mockScanner := newMockScannerWithRealEnablement(ctrl, engine, tc.p, resolver)
			mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).Return([]types.Issue{}, nil).Times(1)

			sc, _ := setupScannerWithResolver(t, engine, tokenService, resolver, mockScanner)
			folderPath := types.FilePath(t.TempDir())
			fc := &types.FolderConfig{FolderPath: folderPath}
			fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
			fp := string(types.PathKey(fc.FolderPath))
			conf.Set(configresolver.UserFolderKey(fp, tc.setting), &configresolver.LocalConfigField{Value: true, Changed: true})
			ctx := ctx2.NewContextWithFolderConfig(t.Context(), fc)
			sc.Scan(ctx, folderPath, types.NoopResultProcessor, nil)
		})

		t.Run(string(tc.p)+"_override_false_over_global_true", func(t *testing.T) {
			engine, tokenService := testutil.UnitTestWithEngine(t)
			ctrl := gomock.NewController(t)
			t.Cleanup(ctrl.Finish)

			enableProduct(engine, tc.p, true)
			resolver, conf := newTestConfigResolver(t)
			setProductEnabledInConf(conf, tc.p, true)

			mockScanner := newMockScannerWithRealEnablement(ctrl, engine, tc.p, resolver)
			mockScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).Times(0)

			sc, _ := setupScannerWithResolver(t, engine, tokenService, resolver, mockScanner)
			folderPath := types.FilePath(t.TempDir())
			fc := &types.FolderConfig{FolderPath: folderPath}
			fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
			fp := string(types.PathKey(fc.FolderPath))
			conf.Set(configresolver.UserFolderKey(fp, tc.setting), &configresolver.LocalConfigField{Value: false, Changed: true})
			ctx := ctx2.NewContextWithFolderConfig(t.Context(), fc)
			sc.Scan(ctx, folderPath, types.NoopResultProcessor, nil)
		})
	}
}

// --- D. Delta Findings Precedence → Used in Scan Pipeline ---

func TestScanPrecedence_DeltaFindings_ResolvedFromConfigResolver(t *testing.T) {
	engine, _ := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), true)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingScanNetNew), false)

	resolver, conf := newTestConfigResolver(t)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingScanNetNew), false)
	conf.Set(configresolver.UserGlobalKey(types.SettingScanAutomatic), true)

	folderPath := types.FilePath(t.TempDir())
	fc := &types.FolderConfig{FolderPath: folderPath}
	fc.ConfigResolver = types.NewMinimalConfigResolver(conf)

	isDelta := resolver.IsDeltaFindingsEnabledForFolder(fc)
	assert.False(t, isDelta, "scan_net_new=false in configuration should yield IsDeltaFindingsEnabledForFolder=false")
}

func TestScanPrecedence_DeltaFindings_UserOverrideOverridesGlobal(t *testing.T) {
	engine, _ := testutil.UnitTestWithEngine(t)

	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingScanNetNew), true)

	resolver, conf := newTestConfigResolver(t)
	conf.Set(configresolver.UserGlobalKey(types.SettingScanNetNew), true)

	folderPath := types.FilePath(t.TempDir())
	fc := &types.FolderConfig{FolderPath: folderPath}
	fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
	fp := string(types.PathKey(fc.FolderPath))
	conf.Set(configresolver.UserFolderKey(fp, types.SettingScanNetNew), &configresolver.LocalConfigField{Value: true, Changed: true})

	isDelta := resolver.IsDeltaFindingsEnabledForFolder(fc)
	assert.True(t, isDelta, "user override should take precedence over global setting")
}

// --- E. Severity Filter Precedence → Used in Scan Results Processing ---

func TestScanPrecedence_SeverityFilter_GlobalSetting(t *testing.T) {
	engine, _ := testutil.UnitTestWithEngine(t)

	expectedFilter := types.SeverityFilter{Critical: true, High: true, Medium: false, Low: false}
	config.SetSeverityFilterOnConfig(engine.GetConfiguration(), &expectedFilter, engine.GetLogger())
	resolver, conf := newTestConfigResolver(t)
	conf.Set(configresolver.UserGlobalKey(types.SettingSeverityFilterCritical), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSeverityFilterHigh), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSeverityFilterMedium), false)
	conf.Set(configresolver.UserGlobalKey(types.SettingSeverityFilterLow), false)

	folderPath := types.FilePath(t.TempDir())
	fc := &types.FolderConfig{FolderPath: folderPath}

	resolvedFilter := resolver.FilterSeverityForFolder(fc)
	assert.Equal(t, expectedFilter, resolvedFilter)
}

func TestScanPrecedence_SeverityFilter_UserOverride(t *testing.T) {
	engine, _ := testutil.UnitTestWithEngine(t)

	globalFilter := types.SeverityFilter{Critical: true, High: true, Medium: true, Low: true}
	config.SetSeverityFilterOnConfig(engine.GetConfiguration(), &globalFilter, engine.GetLogger())
	resolver, conf := newTestConfigResolver(t)
	conf.Set(configresolver.UserGlobalKey(types.SettingSeverityFilterCritical), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSeverityFilterHigh), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSeverityFilterMedium), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSeverityFilterLow), true)

	overrideFilter := &types.SeverityFilter{Critical: true, High: false, Medium: false, Low: false}
	folderPath := types.FilePath(t.TempDir())
	fc := &types.FolderConfig{FolderPath: folderPath}
	fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
	fp := string(types.PathKey(fc.FolderPath))
	conf.Set(configresolver.UserFolderKey(fp, types.SettingSeverityFilterCritical), &configresolver.LocalConfigField{Value: true, Changed: true})
	conf.Set(configresolver.UserFolderKey(fp, types.SettingSeverityFilterHigh), &configresolver.LocalConfigField{Value: false, Changed: true})
	conf.Set(configresolver.UserFolderKey(fp, types.SettingSeverityFilterMedium), &configresolver.LocalConfigField{Value: false, Changed: true})
	conf.Set(configresolver.UserFolderKey(fp, types.SettingSeverityFilterLow), &configresolver.LocalConfigField{Value: false, Changed: true})

	resolvedFilter := resolver.FilterSeverityForFolder(fc)
	assert.Equal(t, *overrideFilter, resolvedFilter, "folder user override should take precedence over global")
}

// --- F. Full Precedence Chain: LDX-Sync + Global + User Override + Locked ---

func TestScanPrecedence_FullPrecedenceChain_OrgScope(t *testing.T) {
	engine, _ := testutil.UnitTestWithEngine(t)

	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), true)

	orgConfig := types.NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(types.SettingSnykCodeEnabled, false, true, "group")
	orgConfig.SetField(types.SettingSnykOssEnabled, true, false, "org")

	resolver, conf := newTestConfigResolver(t)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), false)
	types.WriteOrgConfigToConfiguration(conf, orgConfig)

	folderPath := types.FilePath(t.TempDir())
	fc := &types.FolderConfig{FolderPath: folderPath}
	fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
	fp := string(types.PathKey(fc.FolderPath))
	conf.Set(configresolver.UserFolderKey(fp, types.SettingPreferredOrg), &configresolver.LocalConfigField{Value: "org1", Changed: true})
	conf.Set(configresolver.UserFolderKey(fp, types.SettingOrgSetByUser), &configresolver.LocalConfigField{Value: true, Changed: true})
	conf.Set(configresolver.UserFolderKey(fp, types.SettingSnykCodeEnabled), &configresolver.LocalConfigField{Value: true, Changed: true})
	conf.Set(configresolver.UserFolderKey(fp, types.SettingSnykOssEnabled), &configresolver.LocalConfigField{Value: true, Changed: true})

	t.Run("locked LDX-Sync wins over user override and global", func(t *testing.T) {
		assert.False(t, resolver.IsSnykCodeEnabledForFolder(fc),
			"snyk_code_enabled: LDX-Sync locked=false should win over user_override=true and global=true")
	})

	t.Run("user override wins over non-locked LDX-Sync and global", func(t *testing.T) {
		assert.True(t, resolver.IsSnykOssEnabledForFolder(fc),
			"snyk_oss_enabled: user_override=true should win over global=false (LDX-Sync not locked)")
	})
}

func TestScanPrecedence_FullPrecedenceChain_WithScanner(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), true)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), false)

	orgConfig := types.NewLDXSyncOrgConfig("org1")
	orgConfig.SetField(types.SettingSnykCodeEnabled, false, true, "group")
	orgConfig.SetField(types.SettingSnykOssEnabled, true, false, "org")
	orgConfig.SetField(types.SettingSnykIacEnabled, true, true, "group")

	resolver, conf := newTestConfigResolver(t)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), false)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), false)
	types.WriteOrgConfigToConfiguration(conf, orgConfig)

	folderPath := types.FilePath(t.TempDir())
	fc := &types.FolderConfig{FolderPath: folderPath}
	fc.ConfigResolver = types.NewMinimalConfigResolver(conf)
	fp := string(types.PathKey(fc.FolderPath))
	conf.Set(configresolver.UserFolderKey(fp, types.SettingPreferredOrg), &configresolver.LocalConfigField{Value: "org1", Changed: true})
	conf.Set(configresolver.UserFolderKey(fp, types.SettingOrgSetByUser), &configresolver.LocalConfigField{Value: true, Changed: true})
	conf.Set(configresolver.UserFolderKey(fp, types.SettingSnykCodeEnabled), &configresolver.LocalConfigField{Value: true, Changed: true})
	conf.Set(configresolver.UserFolderKey(fp, types.SettingSnykOssEnabled), &configresolver.LocalConfigField{Value: true, Changed: true})

	codeScanner := newMockScannerWithRealEnablement(ctrl, engine, product.ProductCode, resolver)
	codeScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).Times(0)

	ossScanner := newMockScannerWithRealEnablement(ctrl, engine, product.ProductOpenSource, resolver)
	ossScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).Return([]types.Issue{}, nil).Times(1)

	iacScanner := newMockScannerWithRealEnablement(ctrl, engine, product.ProductInfrastructureAsCode, resolver)
	iacScanner.EXPECT().Scan(gomock.Any(), gomock.Any()).Return([]types.Issue{}, nil).Times(1)

	sc, _ := setupScannerWithResolver(t, engine, tokenService, resolver, codeScanner, ossScanner, iacScanner)
	ctx := ctx2.NewContextWithFolderConfig(t.Context(), fc)
	sc.Scan(ctx, folderPath, types.NoopResultProcessor, nil)
}

// --- Helpers ---

// setProductEnabledInConf writes the product enablement to configuration.
func setProductEnabledInConf(conf configuration.Configuration, p product.Product, enabled bool) {
	switch p {
	case product.ProductCode:
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), enabled)
	case product.ProductOpenSource:
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), enabled)
	case product.ProductInfrastructureAsCode:
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), enabled)
	case product.ProductSecrets:
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled), enabled)
	case product.ProductContainer:
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykContainerEnabled), enabled)
	case product.ProductUnknown:
		// no-op
	}
}

func enableProduct(engine workflow.Engine, p product.Product, enabled bool) {
	conf := engine.GetConfiguration()
	switch p {
	case product.ProductCode:
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), enabled)
	case product.ProductOpenSource:
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), enabled)
	case product.ProductInfrastructureAsCode:
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), enabled)
	case product.ProductSecrets:
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled), enabled)
	case product.ProductContainer:
		conf.Set(configresolver.UserGlobalKey(types.SettingSnykContainerEnabled), enabled)
	case product.ProductUnknown:
		// no-op
	}
}
