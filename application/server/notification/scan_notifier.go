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

package notification

import (
	"encoding/json"
	"errors"
	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

type scanNotifier struct {
	notifier notification.Notifier
	c        *config.Config
}

func NewScanNotifier(c *config.Config, notifier notification.Notifier) (scanner.ScanNotifier, error) {
	if notifier == nil {
		return nil, errors.New("notifier cannot be null")
	}

	return &scanNotifier{
		notifier: notifier,
		c:        c,
	}, nil
}

func (n *scanNotifier) SendError(product product.Product, folderPath string, errorMessage string) {
	cliError := &types.CliError{}
	err := json.Unmarshal([]byte(errorMessage), cliError)
	if err != nil {
		// no structured info available
		cliError = nil
	}

	n.notifier.Send(
		types.SnykScanParams{
			Status:       types.ErrorStatus,
			Product:      product.ToProductCodename(),
			FolderPath:   folderPath,
			ErrorMessage: errorMessage,
			CliError:     cliError,
		},
	)
}

// SendSuccessForAllProducts reports success for all enabled products
func (n *scanNotifier) SendSuccessForAllProducts(folderPath string) {
	for _, p := range n.supportedProducts() {
		if n.isProductEnabled(p) {
			n.sendSuccess(p, folderPath)
		}
	}
}

// SendSuccess sends scan success message for a single enabled product
func (n *scanNotifier) SendSuccess(product product.Product, folderPath string) {
	// If no issues found, we still should send success message the reported product
	n.sendSuccess(product, folderPath)
}

func (n *scanNotifier) sendSuccess(pr product.Product, folderPath string) {
	if !n.isProductEnabled(pr) {
		return
	}

	n.notifier.Send(
		types.SnykScanParams{
			Status:     types.Success,
			Product:    pr.ToProductCodename(),
			FolderPath: folderPath,
		},
	)
}

func (n *scanNotifier) isProductEnabled(p product.Product) bool {
	c := config.CurrentConfig()
	switch p {
	case product.ProductCode:
		return c.IsSnykCodeEnabled() || c.IsSnykCodeQualityEnabled() || c.IsSnykCodeSecurityEnabled()
	case product.ProductOpenSource:
		return c.IsSnykOssEnabled()
	case product.ProductInfrastructureAsCode:
		return c.IsSnykIacEnabled()
	default:
		return false
	}
}

// SendInProgress Notifies all snyk/scan enabled product messages
func (n *scanNotifier) SendInProgress(folderPath string) {
	products := n.supportedProducts()
	for _, pr := range products {
		if !n.isProductEnabled(pr) {
			continue
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

func (n *scanNotifier) supportedProducts() []product.Product {
	products := []product.Product{product.ProductOpenSource, product.ProductInfrastructureAsCode, product.ProductCode}
	return products
}
