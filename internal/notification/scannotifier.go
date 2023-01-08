package notification

import "github.com/snyk/snyk-ls/application/server/lsp"

type ScanNotifier interface {
	SendInProgress(folderPath string)
	SendSuccess(folderPath string) //TODO - add parameter with results
	SendError(folderPath string)
}

type scanNotifier struct {
	productName string
}

func NewNotifier(productName string) ScanNotifier {
	return &scanNotifier{productName: productName}
}

func (n *scanNotifier) SendError(folderPath string) {
	Send(lsp.SnykScanParams{
		Status:  lsp.ErrorStatus,
		Product: n.productName,
	})
}

func (n *scanNotifier) SendSuccess(folderPath string) {
	Send(lsp.SnykScanParams{
		Status:  lsp.Success,
		Product: n.productName,
		//Results: results,
	})
}

func (n *scanNotifier) SendInProgress(folderPath string) {
	Send(lsp.SnykScanParams{
		Status:  lsp.InProgress,
		Product: n.productName,
		//Results: results,
	})
}
