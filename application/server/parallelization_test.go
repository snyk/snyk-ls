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

	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

func Test_Concurrent_CLI_Runs(t *testing.T) {
	engine, tokenService := testutil.SmokeTestWithEngine(t, "", "SMOKE_SHARD_2")
	srv, jsonRPCRecorder, _ := setupServer(t, engine, tokenService, WithRealDI())
	enableOnlyProducts(t, engine, product.ProductOpenSource)
	t.Setenv("SNYK_LOG_LEVEL", "info")
	lspClient := srv.Client

	// create clones and make them workspace folders
	type scanStatus struct {
		status    types.ScanStatus
		scanError string
	}
	scanStatuses := map[types.FilePath]map[product.Product]scanStatus{}

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

		// Track scan statuses for diagnostics; log only on transitions to avoid spam.
		// Both reference-branch and working-copy scans emit $/snyk.scan with the
		// same folderPath/product key, so the last notification wins. This is
		// acceptable: the test exits only after the working-copy scan succeeds, and
		// waitForAllScansToComplete at the end guards against goroutine leaks.
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

			var errMsg string
			if scanParams.PresentableError != nil {
				errMsg = scanParams.PresentableError.ErrorMessage
			}
			ss := scanStatus{status: scanParams.Status, scanError: errMsg}

			prev := scanStatuses[scanParams.FolderPath][p]
			if prev != ss {
				if ss.status == types.ErrorStatus {
					t.Logf("Scan error for folder %s product %s: %s", scanParams.FolderPath, p.ToProductCodename(), ss.scanError)
				} else {
					t.Logf("Scan status changed: folder %s product %s → %s", scanParams.FolderPath, p.ToProductCodename(), ss.status)
				}
			}
			scanStatuses[scanParams.FolderPath][p] = ss
		}

		// Count successful scans
		ossEnabled := engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykOssEnabled))
		iacEnabled := engine.GetConfiguration().GetBool(configresolver.UserGlobalKey(types.SettingSnykIacEnabled))
		received := 0
		for _, productStatuses := range scanStatuses {
			ossSuccess := productStatuses[product.ProductOpenSource].status == types.Success
			iacSuccess := productStatuses[product.ProductInfrastructureAsCode].status == types.Success
			if ossSuccess == ossEnabled && iacSuccess == iacEnabled {
				received++
			}
		}
		return received == len(workspaceFolders)
	}, 10*time.Minute, time.Second, "not all scans were successful")

	// Log final scan state so timeout failures are diagnosable without tracing transition logs.
	t.Logf("Final scan state: %+v", scanStatuses)

	// Wait for reference branch scans to complete so their goroutines don't outlive the test
	// and cause the cleanup shutdown to block for an extended period.
	waitForAllScansToComplete(t, di.ScanStateAggregator())
}
