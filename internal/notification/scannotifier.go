package notification

import "github.com/snyk/snyk-ls/application/server/lsp"

type ScanNotifier interface {
	SendInProgress(folderPath string)
	SendSuccess(folderPath string) //TODO - add parameter with results
	SendError(folderPath string)
}

type scanNotifier struct {
	notifier    Notifier
	productName string
}

func NewScanNotifier(notifier Notifier, productName string) ScanNotifier {
	return &scanNotifier{
		notifier:    notifier,
		productName: productName,
	}
}

func (n *scanNotifier) SendError(folderPath string) {
	n.notifier.Send(lsp.SnykScanParams{
		Status:  lsp.ErrorStatus,
		Product: n.productName,
	})
}

func (n *scanNotifier) SendSuccess(folderPath string) {
	n.notifier.Send(lsp.SnykScanParams{
		Status:  lsp.Success,
		Product: n.productName,
		//Results: results,
	})
}

func (n *scanNotifier) SendInProgress(folderPath string) {
	n.notifier.Send(lsp.SnykScanParams{
		Status:  lsp.InProgress,
		Product: n.productName,
		//Results: results,
	})
}
