/*
 * © 2024 Snyk Limited
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
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

func Test_Concurrent_CLI_Runs(t *testing.T) {
	srv, jsonRPCRecorder := setupServer(t)
	c := testutil.SmokeTest(t, false)
	c.SetSnykIacEnabled(false)
	c.SetSnykOssEnabled(true)
	di.Init()

	lspClient := srv.Client

	// create clones and make them workspace folders
	type scanParamsTuple map[product.Product]bool
	successfulScans := map[string]scanParamsTuple{}

	var workspaceFolders []types.WorkspaceFolder
	for i := 0; i < 10; i++ {
		dir := t.TempDir()
		repo, err := testutil.SetupCustomTestRepo(t, dir, nodejsGoof, "", c.Logger())
		require.NoError(t, err)
		folder := types.WorkspaceFolder{
			Name: fmt.Sprintf("Test Repo %d", i),
			Uri:  uri.PathToUri(repo),
		}
		workspaceFolders = append(workspaceFolders, folder)
		successfulScans[repo] = scanParamsTuple{}
	}

	clientParams := types.InitializeParams{
		WorkspaceFolders: workspaceFolders,
		InitializationOptions: types.Settings{
			Endpoint:                    os.Getenv("SNYK_API"),
			Token:                       os.Getenv("SNYK_TOKEN"),
			EnableTrustedFoldersFeature: "false",
			FilterSeverity:              types.DefaultSeverityFilter(),
			AuthenticationMethod:        types.TokenAuthentication,
			AutomaticAuthentication:     "false",
		},
	}

	lspClient.Call(context.Background(), "initialize", clientParams)
	lspClient.Call(context.Background(), "initialized", nil)

	// check if all scan params were sent
	assert.Eventuallyf(t, func() bool {
		notificationsByMethod := jsonRPCRecorder.FindNotificationsByMethod("$/snyk.scan")
		for _, notification := range notificationsByMethod {
			var scanParams types.SnykScanParams
			err := notification.UnmarshalParams(&scanParams)
			require.NoError(t, err)

			if scanParams.Status == types.Success {
				successfulScans[scanParams.FolderPath][product.ToProduct(scanParams.Product)] = true
			}
		}

		received := 0
		for _, tuple := range successfulScans {
			if tuple[product.ProductOpenSource] == c.IsSnykOssEnabled() && tuple[product.ProductInfrastructureAsCode] == c.IsSnykIacEnabled() {
				received++
			}
		}
		return received == len(workspaceFolders)
	}, time.Minute*5, time.Millisecond*100, "not all scans were successful")
}
