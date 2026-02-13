/*
 * © 2024-2026 Snyk Limited
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

// Package notification implements the scan notifications
package notification

import (
	"encoding/json"
	"errors"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/infrastructure/utils"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

type scanNotifier struct {
	notifier       notification.Notifier
	c              *config.Config
	configResolver types.ConfigResolverInterface
}

func NewScanNotifier(c *config.Config, notifier notification.Notifier, configResolver types.ConfigResolverInterface) (scanner.ScanNotifier, error) {
	if notifier == nil {
		return nil, errors.New("notifier cannot be null")
	}

	return &scanNotifier{
		notifier:       notifier,
		c:              c,
		configResolver: configResolver,
	}, nil
}

func (n *scanNotifier) SendError(product product.Product, folderPath types.FilePath, errorMessage string) {
	cliError := &types.CliError{}
	err := json.Unmarshal([]byte(errorMessage), cliError)
	if err != nil {
		// no structured info available
		cliError.ErrorMessage = errorMessage
	}

	showNotification := true
	treeNodeSuffix := "(scan failed)"

	// Check if this error has specific metadata configured
	if metadata, exists := utils.ErrorConfig[cliError.ErrorMessage]; exists {
		showNotification = metadata.ShowNotification
		treeNodeSuffix = metadata.TreeRootSuffix
	}

	n.notifier.Send(
		types.SnykScanParams{
			Status:     types.ErrorStatus,
			Product:    product.ToProductCodename(),
			FolderPath: folderPath,
			PresentableError: &types.PresentableError{
				CliError:         *cliError,
				ShowNotification: showNotification,
				TreeNodeSuffix:   treeNodeSuffix,
			},
		},
	)
}

// SendSuccessForAllProducts reports success for all enabled products
func (n *scanNotifier) SendSuccessForAllProducts(folderConfig *types.FolderConfig) {
	for _, p := range n.supportedProducts() {
		if n.isProductEnabledForFolder(p, folderConfig) {
			n.sendSuccess(p, folderConfig)
		}
	}
}

// SendSuccess sends scan success message for a single enabled product
func (n *scanNotifier) SendSuccess(pr product.Product, folderConfig *types.FolderConfig) {
	// If no issues found, we still should send success message the reported product
	n.sendSuccess(pr, folderConfig)
}

func (n *scanNotifier) sendSuccess(pr product.Product, folderConfig *types.FolderConfig) {
	if !n.isProductEnabledForFolder(pr, folderConfig) {
		return
	}

	folderPath := types.FilePath("")
	if folderConfig != nil {
		folderPath = folderConfig.FolderPath
	}
	n.notifier.Send(
		types.SnykScanParams{
			Status:     types.Success,
			Product:    pr.ToProductCodename(),
			FolderPath: folderPath,
		},
	)
}

// SendInProgress Notifies all snyk/scan enabled product messages
func (n *scanNotifier) SendInProgress(folderConfig *types.FolderConfig) {
	products := n.supportedProducts()
	for _, pr := range products {
		if !n.isProductEnabledForFolder(pr, folderConfig) {
			continue
		}

		folderPath := types.FilePath("")
		if folderConfig != nil {
			folderPath = folderConfig.FolderPath
		}
		n.notifier.Send(
			types.SnykScanParams{
				Status:     types.InProgress,
				Product:    pr.ToProductCodename(),
				FolderPath: folderPath,
			},
		)
	}
}

func (n *scanNotifier) isProductEnabledForFolder(p product.Product, folderConfig *types.FolderConfig) bool {
	if n.configResolver != nil {
		return n.configResolver.IsProductEnabledForFolder(p, folderConfig)
	}
	switch p {
	case product.ProductCode:
		return n.c.IsSnykCodeEnabled()
	case product.ProductOpenSource:
		return n.c.IsSnykOssEnabled()
	case product.ProductInfrastructureAsCode:
		return n.c.IsSnykIacEnabled()
	default:
		return false
	}
}

func (n *scanNotifier) supportedProducts() []product.Product {
	products := []product.Product{product.ProductOpenSource, product.ProductInfrastructureAsCode, product.ProductCode}
	return products
}
