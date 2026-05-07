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
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

func Test_Concurrent_CLI_Runs(t *testing.T) {
	engine, tokenService := testutil.SmokeTestWithEngine(t, "", "SMOKE_SHARD_2")
	srv, jsonRPCRecorder := setupServer(t, engine, tokenService)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), false)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), true)
	di.Init(engine, tokenService)
	t.Setenv("SNYK_LOG_LEVEL", "info")
	lspClient := srv.Client

	// create clones and make them workspace folders
	type scanStatus struct {
		status types.ScanStatus
		error  string
	}
	scanStatuses := map[types.FilePath]map[product.Product]scanStatus{}
	scanStatusesMu := sync.Mutex{}

	var workspaceFolders []types.WorkspaceFolder
	wg := sync.WaitGroup{}
	mu := sync.Mutex{}
	const folderCount = 3 // enough to test concurrency without excessive CI time
	for i := 0; i < folderCount; i++ {
		intermediateIndex := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			repo := copyGoofDirInto(t, t.TempDir())
			folder := types.WorkspaceFolder{
				Name: fmt.Sprintf("Test Repo %d", intermediateIndex),
				Uri:  uri.PathToUri(repo),
			}
			mu.Lock()
			workspaceFolders = append(workspaceFolders, folder)
			scanStatuses[repo] = map[product.Product]scanStatus{}
			mu.Unlock()
		}()
	}
	wg.Wait()

	// Sort workspaceFolders to ensure deterministic order
	sort.Slice(workspaceFolders, func(i, j int) bool {
		return workspaceFolders[i].Name < workspaceFolders[j].Name
	})

	setUniqueCliPath(t, engine)

	clientParams := types.InitializeParams{
		WorkspaceFolders: workspaceFolders,
		InitializationOptions: types.InitializationOptions{
			Settings: map[string]*types.ConfigSetting{
				types.SettingApiEndpoint:             {Value: os.Getenv("SNYK_API"), Changed: true},
				types.SettingToken:                   {Value: os.Getenv("SNYK_TOKEN"), Changed: true},
				types.SettingTrustEnabled:            {Value: false, Changed: true},
				types.SettingSeverityFilterCritical:  {Value: true, Changed: true},
				types.SettingSeverityFilterHigh:      {Value: true, Changed: true},
				types.SettingSeverityFilterMedium:    {Value: true, Changed: true},
				types.SettingSeverityFilterLow:       {Value: true, Changed: true},
				types.SettingAuthenticationMethod:    {Value: string(types.TokenAuthentication), Changed: true},
				types.SettingAutomaticAuthentication: {Value: false, Changed: true},
				types.SettingAutomaticDownload:       {Value: true, Changed: true},
				types.SettingCliPath:                 {Value: types.GetGlobalString(engine.GetConfiguration(), types.SettingCliPath), Changed: true},
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
		scanStatusesMu.Lock()
		defer scanStatusesMu.Unlock()

		// Track scan statuses for diagnostics
		for _, notification := range notificationsByMethod {
			var scanParams types.SnykScanParams
			err := notification.UnmarshalParams(&scanParams)
			if err != nil {
				continue
			}

			p := product.ToProduct(scanParams.Product)
			if _, exists := scanStatuses[scanParams.FolderPath]; !exists {
				continue
			}

			// Update status for this folder/product combination
			scanStatuses[scanParams.FolderPath][p] = scanStatus{
				status: scanParams.Status,
				error:  "",
			}
			if scanParams.PresentableError != nil {
				scanStatuses[scanParams.FolderPath][p] = scanStatus{
					status: scanParams.Status,
					error:  scanParams.PresentableError.ErrorMessage,
				}
			}
		}

		// Check for errors and log diagnostics
		for folderPath, productStatuses := range scanStatuses {
			for p, status := range productStatuses {
				if status.status == types.ErrorStatus {
					t.Logf("Scan error for folder %s product %s: %s", folderPath, p.ToProductCodename(), status.error)
				}
			}
		}

		// Count successful scans
		ossEnabled := engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykOssEnabled))
		iacEnabled := engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykIacEnabled))
		received := 0
		for folderPath, productStatuses := range scanStatuses {
			ossSuccess := productStatuses[product.ProductOpenSource].status == types.Success
			iacSuccess := productStatuses[product.ProductInfrastructureAsCode].status == types.Success
			if ossSuccess == ossEnabled && iacSuccess == iacEnabled {
				received++
			} else {
				// Log why this folder didn't match
				t.Logf("Folder %s: OSS success=%v (expected=%v), IAC success=%v (expected=%v)",
					folderPath, ossSuccess, ossEnabled, iacSuccess, iacEnabled)
				for p, status := range productStatuses {
					t.Logf("  Product %s: status=%s, error=%s", p.ToProductCodename(), status.status, status.error)
				}
			}
		}
		return received == len(workspaceFolders)
	}, 10*time.Minute, time.Second, "not all scans were successful")
	// Wait for reference branch scans to complete so their goroutines don't outlive the test
	// and cause the cleanup shutdown to block for an extended period.
	waitForAllScansToComplete(t, di.ScanStateAggregator())
}
