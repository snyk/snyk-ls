package notification

import (
	"errors"

	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/domain/ide/notification"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
)

var enabledProducts = map[product.Product]bool{
	product.ProductCode: true,
}

type scanNotifier struct {
	notifier notification.Notifier
}

func NewScanNotifier(notifier notification.Notifier) (snyk.ScanNotifier, error) {
	if notifier == nil {
		return nil, errors.New("notifier cannot be null")
	}

	return &scanNotifier{
		notifier: notifier,
	}, nil
}

func (n *scanNotifier) SendError(pr product.Product, folderPath string) {
	n.notifier.Send(
		lsp.SnykScanParams{
			Status:     lsp.ErrorStatus,
			Product:    product.ToProductCodename(pr),
			FolderPath: folderPath,
		},
	)
}

// Sends scan success message for all enabled products
func (n *scanNotifier) SendSuccess(folderPath string, issues []snyk.Issue) {
	productIssues := make(map[product.Product][]snyk.Issue)

	// if no issues found, we still should send success message for all enabled products
	for pr := range enabledProducts {
		productIssues[pr] = make([]snyk.Issue, 0)
	}

	for _, issue := range issues {
		product := issue.Product
		enabled, ok := enabledProducts[product]
		if !enabled || !ok {
			continue // skip disabled products
		}

		productIssues[product] = append(productIssues[product], issue)
	}

	for pr, issues := range productIssues {
		n.sendSuccess(pr, folderPath, issues)
	}
}

func (n *scanNotifier) sendSuccess(pr product.Product, folderPath string, issues []snyk.Issue) {
	enabled, ok := enabledProducts[pr]
	if !enabled || !ok {
		return
	}

	var scanIssues []lsp.ScanIssue

	for _, issue := range issues {
		additionalData, ok := issue.AdditionalData.(snyk.CodeIssueData) // Will change when OSS communication is added
		if !ok {
			continue // skip non-code issues
		}

		exampleCommitFixes := make([]lsp.ExampleCommitFix, 0, len(additionalData.ExampleCommitFixes))
		for i := range additionalData.ExampleCommitFixes {
			lines := make([]lsp.CommitChangeLine, 0, len(additionalData.ExampleCommitFixes[i].Lines))
			for j := range additionalData.ExampleCommitFixes[i].Lines {
				lines = append(lines, lsp.CommitChangeLine{
					Line:       additionalData.ExampleCommitFixes[i].Lines[j].Line,
					LineNumber: additionalData.ExampleCommitFixes[i].Lines[j].LineNumber,
					LineChange: additionalData.ExampleCommitFixes[i].Lines[j].LineChange,
				})
			}
			exampleCommitFixes = append(exampleCommitFixes, lsp.ExampleCommitFix{
				CommitURL: additionalData.ExampleCommitFixes[i].CommitURL,
				Lines:     lines,
			})
		}
		scanIssues = append(scanIssues, lsp.ScanIssue{
			Id:       issue.ID,
			Title:    "Title",
			Severity: issue.Severity.String(),
			FilePath: issue.AffectedFilePath,
			AdditionalData: lsp.CodeIssueData{
				Message:            additionalData.Message,
				Rule:               additionalData.Rule,
				RepoDatasetSize:    additionalData.RepoDatasetSize,
				ExampleCommitFixes: exampleCommitFixes,
				CWE:                additionalData.CWE,
				IsSecurityType:     additionalData.IsSecurityType,
				Text:               additionalData.Text,
				Cols:               additionalData.Cols,
				Rows:               additionalData.Rows,

				// TODO - fill these with real data
				Markers: nil,
				LeadURL: "",
			},
		})
	}

	n.notifier.Send(
		lsp.SnykScanParams{
			Status:     lsp.Success,
			Product:    product.ToProductCodename(pr),
			FolderPath: folderPath,
			Issues:     scanIssues,
		},
	)
}

// Notifies all snyk/scan enabled product messages
func (n *scanNotifier) SendInProgress(folderPath string) {
	// todo: check if config.product is enabled
	for pr, enabled := range enabledProducts {
		if !enabled {
			continue
		}

		n.notifier.Send(
			lsp.SnykScanParams{
				Status:     lsp.InProgress,
				Product:    product.ToProductCodename(pr),
				FolderPath: folderPath,
				Issues:     nil,
			},
		)
	}
}
