package notification

import "github.com/snyk/snyk-ls/application/server/lsp"

type ScanNotifier interface {
	SendInProgress()
	SendSuccess() //TODO - add parameter with results
	SendError()
}

type scanNotifier struct {
	productName string
}

func (n *scanNotifier) SendError() {
	Send(lsp.SnykScanParams{
		Status:  lsp.ErrorStatus,
		Product: n.productName,
	})
}

func NewNotifier(productName string) ScanNotifier {
	return &scanNotifier{productName: productName}
}

func (n *scanNotifier) SendSuccess() {
	Send(lsp.SnykScanParams{
		Status:  lsp.Success,
		Product: n.productName,
		//Results: results,
	})
}

func (n *scanNotifier) SendInProgress() {
	Send(lsp.SnykScanParams{
		Status:  lsp.InProgress,
		Product: n.productName,
		//Results: results,
	})
}
