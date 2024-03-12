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
	"errors"
	"strconv"

	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/ide/notification"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/lsp"
	"github.com/snyk/snyk-ls/internal/product"
)

var enabledProducts = map[product.Product]bool{
	product.ProductCode:                 true,
	product.ProductInfrastructureAsCode: true,
	product.ProductOpenSource:           true,
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

// Reports success for all enabled products
func (n *scanNotifier) SendSuccessForAllProducts(folderPath string, issues []snyk.Issue) {
	for product, enabled := range enabledProducts {
		if enabled {
			n.sendSuccess(product, folderPath, issues)
		}
	}
}

// Sends scan success message for a single enabled product
func (n *scanNotifier) SendSuccess(reportedProduct product.Product, folderPath string, issues []snyk.Issue) {
	// If no issues found, we still should send success message the reported product
	productIssues := make([]snyk.Issue, 0)

	for _, issue := range issues {
		product := issue.Product
		enabled, ok := enabledProducts[product]
		if !enabled || !ok {
			continue // skip disabled products
		}

		productIssues = append(productIssues, issue)
	}

	n.sendSuccess(reportedProduct, folderPath, productIssues)
}

func (n *scanNotifier) sendSuccess(pr product.Product, folderPath string, issues []snyk.Issue) {
	enabled, ok := enabledProducts[pr]
	if !enabled || !ok {
		return
	}

	var scanIssues []lsp.ScanIssue
	// check product type
	if pr == product.ProductInfrastructureAsCode {
		scanIssues = n.appendIacIssues(scanIssues, folderPath, issues)
	} else if pr == product.ProductCode {
		scanIssues = n.appendCodeIssues(scanIssues, folderPath, issues)
	} else if pr == product.ProductOpenSource {
		scanIssues = n.appendOssIssues(scanIssues, folderPath, issues)
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

func (n *scanNotifier) appendOssIssues(scanIssues []lsp.ScanIssue, folderPath string, issues []snyk.Issue) []lsp.ScanIssue {
	for _, issue := range issues {
		additionalData, ok := issue.AdditionalData.(snyk.OssIssueData)
		if !ok {
			continue // skip non-oss issues
		}

		scanIssues = append(scanIssues, lsp.ScanIssue{
			Id:       additionalData.Key,
			Title:    additionalData.Title,
			Severity: issue.Severity.String(),
			FilePath: issue.AffectedFilePath,
			Range:    converter.ToRange(issue.Range),
			AdditionalData: lsp.OssIssueData{
				License: additionalData.License,
				Identifiers: lsp.OssIdentifiers{
					CWE: issue.CWEs,
					CVE: issue.CVEs,
				},
				Description:       additionalData.Description,
				Language:          additionalData.Language,
				PackageManager:    additionalData.PackageManager,
				PackageName:       additionalData.PackageName,
				Name:              additionalData.Name,
				Version:           additionalData.Version,
				Exploit:           additionalData.Exploit,
				CVSSv3:            additionalData.CVSSv3,
				CvssScore:         strconv.FormatFloat(additionalData.CvssScore, 'f', 2, 64), // convert float64 to string with 2 decimal places
				FixedIn:           additionalData.FixedIn,
				From:              additionalData.From,
				UpgradePath:       additionalData.UpgradePath,
				IsPatchable:       additionalData.IsPatchable,
				IsUpgradable:      additionalData.IsUpgradable,
				ProjectName:       additionalData.ProjectName,
				DisplayTargetFile: additionalData.DisplayTargetFile,
				Details:           additionalData.Details,
			},
		})
	}

	return scanIssues
}

func (n *scanNotifier) appendIacIssues(scanIssues []lsp.ScanIssue, folderPath string, issues []snyk.Issue) []lsp.ScanIssue {
	for _, issue := range issues {
		additionalData, ok := issue.AdditionalData.(snyk.IaCIssueData)
		if !ok {
			continue // skip non-iac issues
		}

		scanIssues = append(scanIssues, lsp.ScanIssue{
			Id:       additionalData.Key,
			Title:    additionalData.Title,
			Severity: issue.Severity.String(),
			FilePath: issue.AffectedFilePath,
			Range:    converter.ToRange(issue.Range),
			AdditionalData: lsp.IacIssueData{
				PublicId:      additionalData.PublicId,
				Documentation: additionalData.Documentation,
				LineNumber:    additionalData.LineNumber,
				Issue:         additionalData.Issue,
				Impact:        additionalData.Impact,
				Resolve:       additionalData.Resolve,
				Path:          additionalData.Path,
				References:    additionalData.References,
			},
		})
	}
	return scanIssues
}

func (n *scanNotifier) appendCodeIssues(scanIssues []lsp.ScanIssue, folderPath string, issues []snyk.Issue) []lsp.ScanIssue {
	for _, issue := range issues {
		additionalData, ok := issue.AdditionalData.(snyk.CodeIssueData)
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

		markers := make([]lsp.Marker, 0, len(additionalData.Markers))
		for _, marker := range additionalData.Markers {
			positions := make([]lsp.MarkerPosition, 0)
			for _, pos := range marker.Pos {
				positions = append(positions, lsp.MarkerPosition{
					Position: lsp.Position{
						Rows: pos.Rows,
						Cols: pos.Cols,
					},
					File: pos.File,
				})
			}

			markers = append(markers, lsp.Marker{
				Msg: marker.Msg,
				Pos: positions,
			})
		}

		dataFlow := make([]lsp.DataflowElement, 0, len(additionalData.DataFlow))
		for _, flow := range additionalData.DataFlow {
			dataFlow = append(dataFlow, lsp.DataflowElement{
				Position:  flow.Position,
				FilePath:  flow.FilePath,
				FlowRange: converter.ToRange(flow.FlowRange),
				Content:   flow.Content,
			})
		}

		scanIssue := lsp.ScanIssue{
			Id:        additionalData.Key,
			Title:     issue.Message,
			Severity:  issue.Severity.String(),
			FilePath:  issue.AffectedFilePath,
			Range:     converter.ToRange(issue.Range),
			IsIgnored: issue.IsIgnored,
			AdditionalData: lsp.CodeIssueData{
				Message:            additionalData.Message,
				Rule:               additionalData.Rule,
				RuleId:             additionalData.RuleId,
				RepoDatasetSize:    additionalData.RepoDatasetSize,
				ExampleCommitFixes: exampleCommitFixes,
				CWE:                additionalData.CWE,
				IsSecurityType:     additionalData.IsSecurityType,
				Text:               additionalData.Text,
				Cols:               additionalData.Cols,
				Rows:               additionalData.Rows,
				PriorityScore:      additionalData.PriorityScore,
				Markers:            markers,
				LeadURL:            "",
				HasAIFix:           additionalData.HasAIFix,
				DataFlow:           dataFlow,
			},
		}
		if scanIssue.IsIgnored {
			scanIssue.IgnoreDetails =
				lsp.IgnoreDetails{
					Category:   issue.IgnoreDetails.Category,
					Reason:     issue.IgnoreDetails.Reason,
					Expiration: issue.IgnoreDetails.Expiration,
					IgnoredOn:  issue.IgnoreDetails.IgnoredOn,
					IgnoredBy:  issue.IgnoreDetails.IgnoredBy,
				}
		}
		scanIssues = append(scanIssues, scanIssue)
	}

	return scanIssues
}

// Notifies all snyk/scan enabled product messages
func (n *scanNotifier) SendInProgress(folderPath string) {
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
