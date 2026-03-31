/*
 * © 2024-2025 Snyk Limited
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

package server

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/internal/folderconfig"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

func Test_Concurrent_CLI_Runs(t *testing.T) {
	testutil.SkipLocally(t) // skip locally because it's downloading the cli
	engine, tokenService := testutil.SmokeTestWithEngine(t, "")
	srv, jsonRPCRecorder := setupServer(t, engine, tokenService)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), false)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), true)
	di.Init(engine, tokenService)
	t.Setenv("SNYK_LOG_LEVEL", "info")
	lspClient := srv.Client

	// create clones and make them workspace folders
	type scanParamsTuple map[product.Product]bool
	successfulScans := map[types.FilePath]scanParamsTuple{}

	var workspaceFolders []types.WorkspaceFolder
	wg := sync.WaitGroup{}
	mu := sync.Mutex{}
	const folderCount = 3 // enough to test concurrency without excessive CI time
	for i := 0; i < folderCount; i++ {
		intermediateIndex := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			dir := types.FilePath(t.TempDir())
			repo, err := folderconfig.SetupCustomTestRepo(t, dir, testsupport.NodejsGoof, "", engine.GetLogger(), false)
			require.NoError(t, err)
			folder := types.WorkspaceFolder{
				Name: fmt.Sprintf("Test Repo %d", intermediateIndex),
				Uri:  uri.PathToUri(repo),
			}
			mu.Lock()
			workspaceFolders = append(workspaceFolders, folder)
			successfulScans[repo] = scanParamsTuple{}
			mu.Unlock()
		}()
	}
	wg.Wait()

	setUniqueCliPath(t, engine)

	clientParams := types.InitializeParams{
		WorkspaceFolders: workspaceFolders,
		InitializationOptions: types.InitializationOptions{
			Settings: map[string]*types.ConfigSetting{
				types.SettingApiEndpoint:             {Value: os.Getenv("SNYK_API"), Changed: true},
				types.SettingToken:                   {Value: os.Getenv("SNYK_TOKEN"), Changed: true},
				types.SettingTrustEnabled:            {Value: false, Changed: true},
				types.SettingEnabledSeverities:       {Value: map[string]interface{}{"critical": true, "high": true, "medium": true, "low": true}, Changed: true},
				types.SettingAuthenticationMethod:    {Value: string(types.TokenAuthentication), Changed: true},
				types.SettingAutomaticAuthentication: {Value: false, Changed: true},
				types.SettingAutomaticDownload:       {Value: true, Changed: true},
				types.SettingCliPath:                 {Value: engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingCliPath)), Changed: true},
				types.SettingSnykOssEnabled:          {Value: true, Changed: true},
				types.SettingSnykIacEnabled:          {Value: false, Changed: true},
			},
		},
	}

	_, _ = lspClient.Call(t.Context(), "initialize", clientParams)
	_, _ = lspClient.Call(t.Context(), "initialized", nil)

	// check if all scan params were sent
	assert.Eventuallyf(t, func() bool {
		notificationsByMethod := jsonRPCRecorder.FindNotificationsByMethod("$/snyk.scan")
		for _, notification := range notificationsByMethod {
			var scanParams types.SnykScanParams
			err := notification.UnmarshalParams(&scanParams)
			if err != nil {
				continue
			}

			if scanParams.Status == types.Success {
				successfulScans[scanParams.FolderPath][product.ToProduct(scanParams.Product)] = true
			}
		}

		received := 0
		for _, tuple := range successfulScans {
			if tuple[product.ProductOpenSource] == engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykOssEnabled)) && tuple[product.ProductInfrastructureAsCode] == engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykIacEnabled)) {
				received++
			}
		}
		return received == len(workspaceFolders)
	}, 10*time.Minute, time.Second, "not all scans were successful")
	// Wait for reference branch scans to complete so their goroutines don't outlive the test
	// and cause the cleanup shutdown to block for an extended period.
	waitForAllScansToComplete(t, di.ScanStateAggregator())
}
