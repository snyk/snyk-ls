package notification

import (
	"errors"

	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/domain/ide/notification"
	"github.com/snyk/snyk-ls/domain/snyk"
)

type scanNotifier struct {
	notifier    notification.Notifier
	productName string
}

func NewScanNotifier(notifier notification.Notifier, productName string) (snyk.ScanNotifier, error) {
	if notifier == nil {
		return nil, errors.New("notifier cannot be null")
	}
	if productName == "" {
		return nil, errors.New("product name cannot be empty")
	}
	return &scanNotifier{
		notifier:    notifier,
		productName: productName,
	}, nil
}

func (n *scanNotifier) SendError(folderPath string) {
	n.notifier.Send(
		lsp.SnykScanParams{
			Status:     lsp.ErrorStatus,
			Product:    n.productName,
			FolderPath: folderPath,
		},
	)
}

func (n *scanNotifier) SendSuccess(folderPath string) {
	n.notifier.Send(
		lsp.SnykScanParams{
			Status:     lsp.Success,
			Product:    n.productName,
			FolderPath: folderPath,
			//Results: results,
		},
	)
}

func (n *scanNotifier) SendInProgress(folderPath string) {
	n.notifier.Send(
		lsp.SnykScanParams{
			Status:     lsp.InProgress,
			Product:    n.productName,
			FolderPath: folderPath,
			//Results: results,
		},
	)
}
