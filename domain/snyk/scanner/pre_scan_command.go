/*
 * © 2025 Snyk Limited
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

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/scans"
	"github.com/snyk/snyk-ls/internal/types"
)

func (sc *DelegatingConcurrentScanner) executePreScanCommand(
	ctx context.Context,
	c *config.Config,
	p product.Product,
	folderConfig *types.FolderConfig,
	scanDir types.FilePath,
	isNotReferenceScan bool,
) error {
	commandConfig := folderConfig.ScanCommandConfig

	if shouldNotScan(commandConfig, p, isNotReferenceScan) {
		return nil
	}

	preScanCommand := scans.NewPreScanCommand(c.Engine().GetConfiguration(), scanDir, types.FilePath(commandConfig[p].PreScanCommand), c.Logger())
	return preScanCommand.ExecutePreScanCommand(ctx)
}

func shouldNotScan(commandConfig map[product.Product]types.ScanCommandConfig, p product.Product, isNotReferenceScan bool) bool {
	return commandConfig == nil || commandConfig[p].PreScanCommand == "" || commandConfig[p].PreScanOnlyReferenceFolder && isNotReferenceScan
}
