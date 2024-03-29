package snyk

import "github.com/snyk/snyk-ls/internal/product"

type ScanNotifier interface {
	SendInProgress(folderPath string)
	SendSuccess(product product.Product, folderPath string, issues []Issue)
	SendSuccessForAllProducts(folderPath string, issues []Issue)
	SendError(product product.Product, folderPath string)
}
