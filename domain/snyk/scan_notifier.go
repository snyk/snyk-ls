package snyk

import "github.com/snyk/snyk-ls/internal/product"

type ScanNotifier interface {
	SendInProgress(folderPath string)
	SendSuccess(product product.Product, folderPath string)
	SendSuccessForAllProducts(folderPath string)
	SendError(product product.Product, folderPath string, errorMessage string)
}
