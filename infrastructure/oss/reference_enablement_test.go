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

package oss

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/subosito/gotenv"

	"github.com/snyk/snyk-ls/infrastructure/cli/mock_cli"
	"github.com/snyk/snyk-ls/infrastructure/utils"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func newReferenceOSSScanner(
	t *testing.T,
	token string,
) (*CLIScanner, *bool, *types.ConfigResolver, types.FilePath) {
	t.Helper()
	engine, tokenService := testutil.UnitTestWithEngine(t)
	tokenService.SetToken(engine.GetConfiguration(), token)
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), false)

	realFolder := types.FilePath(t.TempDir())
	referenceFolder := types.FilePath(t.TempDir())
	require.NoError(t, os.WriteFile(filepath.Join(string(referenceFolder), "package.json"), []byte(`{"name":"reference"}`), 0o600))
	types.SetFolderUserSetting(conf, realFolder, types.SettingSnykOssEnabled, true)

	resolver := testutil.DefaultConfigResolver(engine)
	require.True(t, resolver.IsProductEnabledForFolder(product.ProductOpenSource, &types.FolderConfig{FolderPath: realFolder}))
	require.False(t, resolver.IsProductEnabledForFolder(product.ProductOpenSource, &types.FolderConfig{FolderPath: referenceFolder}))

	ctrl := gomock.NewController(t)
	executor := mock_cli.NewMockExecutor(ctrl)
	executor.EXPECT().
		ExpandParametersFromConfig(gomock.Any(), gomock.Any()).
		DoAndReturn(func(base []string, _ *types.FolderConfig) []string { return base }).
		AnyTimes()
	executed := false
	executor.EXPECT().
		Execute(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(context.Context, []string, types.FilePath, gotenv.Env) ([]byte, error) {
			executed = true
			return []byte("{}"), nil
		}).
		AnyTimes()
	scanner := NewCLIScanner(
		engine,
		performance.NewInstrumentor(),
		error_reporting.NewTestErrorReporter(engine),
		executor,
		getLearnMock(t),
		notification.NewMockNotifier(),
		resolver,
		testutil.NewDrainedProgressTracker(),
	).(*CLIScanner)
	return scanner, &executed, resolver, referenceFolder
}

func TestCLIScanner_Scan_ReferenceBypassesOnlySyntheticFolderEnablement(t *testing.T) {
	tests := []struct {
		name        string
		scanTypes   []ctx2.DeltaScanType
		expectedErr string
		executed    bool
	}{
		{name: "reference reaches CLI executor", scanTypes: []ctx2.DeltaScanType{ctx2.Reference}, executed: true},
		{name: "working directory remains disabled", scanTypes: []ctx2.DeltaScanType{ctx2.WorkingDirectory}, expectedErr: utils.ErrSnykOssNotEnabledForFolder},
		{name: "missing scan type remains disabled", expectedErr: utils.ErrSnykOssNotEnabledForFolder},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, executed, resolver, referenceFolder := newReferenceOSSScanner(t, "valid-token")

			issues, err := scanner.Scan(testutil.ContextWithFolderScan(t, resolver, referenceFolder, tt.scanTypes...), referenceFolder)

			if tt.expectedErr != "" {
				require.EqualError(t, err, tt.expectedErr)
				assert.Nil(t, issues)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.executed, *executed)
		})
	}
}

func TestCLIScanner_Scan_ReferenceStillRequiresAuthentication(t *testing.T) {
	scanner, executed, resolver, referenceFolder := newReferenceOSSScanner(t, "")

	issues, err := scanner.Scan(
		testutil.ContextWithFolderScan(t, resolver, referenceFolder, ctx2.Reference),
		referenceFolder,
	)

	require.EqualError(t, err, utils.MsgNotAuthenticatedNoScan)
	assert.Nil(t, issues)
	assert.False(t, *executed)
}

func TestCLIScanner_Scan_ReferenceStillSkipsUnsupportedPath(t *testing.T) {
	scanner, executed, resolver, referenceFolder := newReferenceOSSScanner(t, "valid-token")
	unsupportedPath := types.FilePath(filepath.Join(string(referenceFolder), "main.go"))
	require.NoError(t, os.WriteFile(string(unsupportedPath), []byte("package main"), 0o600))

	issues, err := scanner.Scan(
		testutil.ContextWithFolderScan(t, resolver, referenceFolder, ctx2.Reference),
		unsupportedPath,
	)

	require.NoError(t, err)
	assert.Empty(t, issues)
	assert.False(t, *executed)
}
