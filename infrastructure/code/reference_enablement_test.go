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

package code

import (
	"testing"

	codeClient "github.com/snyk/code-client-go"
	"github.com/snyk/code-client-go/pkg/code/sast_contract"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/infrastructure/utils"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func newReferenceCodeScanner(
	t *testing.T,
	token string,
	sastEnabled bool,
) (*Scanner, *types.ConfigResolver, types.FilePath, *int) {
	t.Helper()
	engine, tokenService := testutil.UnitTestWithEngine(t)
	mockEngine, conf := testutil.SetUpEngineMock(t, engine)
	tokenService.SetToken(conf, token)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), false)

	realFolder := types.FilePath(t.TempDir())
	_, referenceFolder := TempWorkdirWithIssues(t)
	types.SetFolderUserSetting(conf, realFolder, types.SettingSnykCodeEnabled, true)
	types.SetSastSettings(conf, referenceFolder, &sast_contract.SastResponse{SastEnabled: sastEnabled})
	types.SetPreferredOrgAndOrgSetByUser(conf, referenceFolder, "test-org", true)

	resolver := testutil.DefaultConfigResolver(mockEngine)
	require.True(t, resolver.IsProductEnabledForFolder(product.ProductCode, &types.FolderConfig{FolderPath: realFolder}))
	require.False(t, resolver.IsProductEnabledForFolder(product.ProductCode, &types.FolderConfig{FolderPath: referenceFolder}))

	factoryCalls := 0
	factory := func(sc *Scanner, folderConfig *types.FolderConfig) (codeClient.CodeScanner, error) {
		factoryCalls++
		return NewFakeCodeScannerClient(sc, folderConfig)
	}
	flags := featureflag.NewFakeService()
	flags.Conf = conf
	flags.SastSettings = &sast_contract.SastResponse{SastEnabled: sastEnabled}
	scanner := New(
		mockEngine,
		performance.NewInstrumentor(),
		&snyk_api.FakeApiClient{CodeEnabled: true},
		newTestCodeErrorReporter(),
		setupMockLearnServiceNoLessons(t),
		flags,
		notification.NewNotifier(),
		NewCodeInstrumentor(),
		newTestCodeErrorReporter(),
		factory,
		resolver,
		testutil.NewDrainedProgressTracker(),
	)
	return scanner, resolver, referenceFolder, &factoryCalls
}

func TestScanner_Scan_ReferenceBypassesOnlySyntheticFolderEnablement(t *testing.T) {
	tests := []struct {
		name         string
		scanTypes    []ctx2.DeltaScanType
		expectedErr  string
		factoryCalls int
	}{
		{name: "reference reaches code scanner factory", scanTypes: []ctx2.DeltaScanType{ctx2.Reference}, factoryCalls: 1},
		{name: "working directory remains disabled", scanTypes: []ctx2.DeltaScanType{ctx2.WorkingDirectory}, expectedErr: utils.ErrSnykCodeNotEnabledForFolder},
		{name: "missing scan type remains disabled", expectedErr: utils.ErrSnykCodeNotEnabledForFolder},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, resolver, referenceFolder, factoryCalls := newReferenceCodeScanner(t, "valid-token", true)

			issues, err := scanner.Scan(testutil.ContextWithFolderScan(t, resolver, referenceFolder, tt.scanTypes...), referenceFolder)

			if tt.expectedErr != "" {
				require.EqualError(t, err, tt.expectedErr)
				assert.Nil(t, issues)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.factoryCalls, *factoryCalls)
		})
	}
}

func TestScanner_Scan_ReferenceStillRequiresAuthentication(t *testing.T) {
	scanner, resolver, referenceFolder, factoryCalls := newReferenceCodeScanner(t, "", true)

	issues, err := scanner.Scan(
		testutil.ContextWithFolderScan(t, resolver, referenceFolder, ctx2.Reference),
		referenceFolder,
	)

	require.EqualError(t, err, utils.MsgNotAuthenticatedNoScan)
	assert.Nil(t, issues)
	assert.Zero(t, *factoryCalls)
}

func TestScanner_Scan_ReferenceStillRequiresSastEnabled(t *testing.T) {
	scanner, resolver, referenceFolder, factoryCalls := newReferenceCodeScanner(t, "valid-token", false)

	issues, err := scanner.Scan(
		testutil.ContextWithFolderScan(t, resolver, referenceFolder, ctx2.Reference),
		referenceFolder,
	)

	require.EqualError(t, err, utils.ErrSnykCodeNotEnabled)
	assert.Nil(t, issues)
	assert.Zero(t, *factoryCalls)
}
