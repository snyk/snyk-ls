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

package secrets

import (
	"testing"

	"github.com/golang/mock/gomock"
	cli_errors "github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/infrastructure/utils"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func newReferenceEnablementScanner(
	t *testing.T,
	token string,
) (*Scanner, *mocks.MockEngine, *types.ConfigResolver, types.FilePath, types.FilePath) {
	t.Helper()
	engine, tokenService := testutil.UnitTestWithEngine(t)
	mockEngine, conf := testutil.SetUpEngineMock(t, engine)
	tokenService.SetToken(conf, token)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled), false)

	realFolder := types.FilePath(t.TempDir())
	referenceFolder := types.FilePath(t.TempDir())
	types.SetFolderUserSetting(conf, realFolder, types.SettingSnykSecretsEnabled, true)

	resolver := testutil.DefaultConfigResolver(mockEngine)
	require.True(t, resolver.IsProductEnabledForFolder(product.ProductSecrets, &types.FolderConfig{FolderPath: realFolder}))
	require.False(t, resolver.IsProductEnabledForFolder(product.ProductSecrets, &types.FolderConfig{FolderPath: referenceFolder}))

	scanner := New(
		conf,
		mockEngine,
		engine.GetLogger(),
		performance.NewInstrumentor(),
		&snyk_api.FakeApiClient{},
		notification.NewMockNotifier(),
		resolver,
	)
	return scanner, mockEngine, resolver, realFolder, referenceFolder
}

func TestScanner_Scan_ReferenceBypassesOnlySyntheticFolderEnablement(t *testing.T) {
	tests := []struct {
		name        string
		scanTypes   []ctx2.DeltaScanType
		invoke      bool
		expectedErr string
	}{
		{name: "reference reaches secrets workflow", scanTypes: []ctx2.DeltaScanType{ctx2.Reference}, invoke: true},
		{name: "working directory remains disabled", scanTypes: []ctx2.DeltaScanType{ctx2.WorkingDirectory}, expectedErr: utils.ErrSnykSecretsNotEnabledForFolder},
		{name: "missing scan type remains disabled", expectedErr: utils.ErrSnykSecretsNotEnabledForFolder},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, mockEngine, resolver, _, referenceFolder := newReferenceEnablementScanner(t, "valid-token")
			if tt.invoke {
				mockEngine.EXPECT().
					InvokeWithConfig(workflow.NewWorkflowIdentifier("secrets.test"), gomock.Any()).
					Return([]workflow.Data{}, nil)
			}

			issues, err := scanner.Scan(
				testutil.ContextWithFolderScan(t, resolver, referenceFolder, tt.scanTypes...),
				referenceFolder,
			)

			if tt.expectedErr != "" {
				require.EqualError(t, err, tt.expectedErr)
				assert.Nil(t, issues)
				return
			}
			require.NoError(t, err)
			assert.Empty(t, issues)
		})
	}
}

func TestScanner_Scan_ReferenceStillRequiresAuthentication(t *testing.T) {
	scanner, _, resolver, _, referenceFolder := newReferenceEnablementScanner(t, "")

	issues, err := scanner.Scan(
		testutil.ContextWithFolderScan(t, resolver, referenceFolder, ctx2.Reference),
		referenceFolder,
	)

	require.EqualError(t, err, utils.MsgNotAuthenticatedNoScan)
	assert.Nil(t, issues)
}

func TestScanner_Scan_ReferenceStillNormalizesWorkflowEntitlement(t *testing.T) {
	scanner, mockEngine, resolver, _, referenceFolder := newReferenceEnablementScanner(t, "valid-token")
	mockEngine.EXPECT().
		InvokeWithConfig(workflow.NewWorkflowIdentifier("secrets.test"), gomock.Any()).
		Return(nil, cli_errors.NewFeatureNotEnabledError("secrets not enabled for org."))

	issues, err := scanner.Scan(
		testutil.ContextWithFolderScan(t, resolver, referenceFolder, ctx2.Reference),
		referenceFolder,
	)

	require.EqualError(t, err, utils.ErrSnykSecretsNotEnabled)
	assert.Nil(t, issues)
}

func TestScanner_Scan_ReferenceWithRemoteOrgFolderEnablement(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	mockEngine, conf := testutil.SetUpEngineMock(t, engine)
	tokenService.SetToken(conf, "valid-token")
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled), false)

	const orgID = "org-with-folder-policy"
	realFolder := types.FilePath(t.TempDir())
	referenceFolder := types.FilePath(t.TempDir())
	types.SetPreferredOrgAndOrgSetByUser(conf, realFolder, orgID, true)
	types.WriteFolderConfigToConfiguration(conf, orgID, realFolder, map[string]*types.LDXSyncField{
		types.SettingSnykSecretsEnabled: {Value: true, OriginScope: "org"},
	})

	resolver := testutil.DefaultConfigResolver(mockEngine)
	require.True(t, resolver.IsProductEnabledForFolder(product.ProductSecrets, &types.FolderConfig{FolderPath: realFolder}))
	require.False(t, resolver.IsProductEnabledForFolder(product.ProductSecrets, &types.FolderConfig{FolderPath: referenceFolder}))
	require.Nil(t, conf.Get(configresolver.RemoteOrgFolderKey(orgID, string(types.PathKey(referenceFolder)), types.SettingSnykSecretsEnabled)))

	mockEngine.EXPECT().
		InvokeWithConfig(workflow.NewWorkflowIdentifier("secrets.test"), gomock.Any()).
		Return([]workflow.Data{}, nil)
	scanner := New(conf, mockEngine, engine.GetLogger(), performance.NewInstrumentor(), &snyk_api.FakeApiClient{}, notification.NewMockNotifier(), resolver)

	issues, err := scanner.Scan(
		testutil.ContextWithFolderScan(t, resolver, referenceFolder, ctx2.Reference),
		referenceFolder,
	)

	require.NoError(t, err)
	assert.Empty(t, issues)
}
