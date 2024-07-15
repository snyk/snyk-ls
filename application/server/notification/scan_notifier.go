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
	"fmt"
	"strconv"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

type scanNotifier struct {
	notifier notification.Notifier
	c        *config.Config
}

func NewScanNotifier(c *config.Config, notifier notification.Notifier) (snyk.ScanNotifier, error) {
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
func (n *scanNotifier) SendSuccessForAllProducts(folderPath string, issues []snyk.Issue) {
	for _, p := range n.supportedProducts() {
		if n.isProductEnabled(p) {
			n.sendSuccess(p, folderPath, issues)
		}
	}
}

// SendSuccess sends scan success message for a single enabled product
func (n *scanNotifier) SendSuccess(reportedProduct product.Product, folderPath string, issues []snyk.Issue) {
	// If no issues found, we still should send success message the reported product
	productIssues := make([]snyk.Issue, 0)

	for _, issue := range issues {
		p := issue.Product
		if !n.isProductEnabled(p) {
			continue // skip disabled products
		}

		if uri.FolderContains(folderPath, issue.AffectedFilePath) {
			productIssues = append(productIssues, issue)
		} else {
			msg := fmt.Sprintf("got an issue that is not contained in the folder: %v", issue)
			n.c.Logger().Error().Str("method", "scanNotifier.SendSuccess").Msgf(msg)
		}
	}

	n.sendSuccess(reportedProduct, folderPath, productIssues)
}

func (n *scanNotifier) sendSuccess(pr product.Product, folderPath string, issues []snyk.Issue) {
	if !n.isProductEnabled(pr) {
		return
	}

	var scanIssues []types.ScanIssue
	// check product type
	if pr == product.ProductInfrastructureAsCode {
		scanIssues = n.appendIacIssues(scanIssues, issues)
	} else if pr == product.ProductCode {
		scanIssues = n.appendCodeIssues(scanIssues, issues)
	} else if pr == product.ProductOpenSource {
		scanIssues = n.appendOssIssues(scanIssues, issues)
	}

	n.notifier.Send(
		types.SnykScanParams{
			Status:     types.Success,
			Product:    pr.ToProductCodename(),
			FolderPath: folderPath,
			Issues:     scanIssues,
		},
	)
}

func (n *scanNotifier) appendOssIssues(scanIssues []types.ScanIssue, issues []snyk.Issue) []types.ScanIssue {
	for _, issue := range issues {
		additionalData, ok := issue.AdditionalData.(snyk.OssIssueData)
		if !ok {
			continue // skip non-oss issues
		}

		matchingIssues := make([]types.OssIssueData, len(additionalData.MatchingIssues))
		for i, matchingIssue := range additionalData.MatchingIssues {
			matchingIssues[i] = types.OssIssueData{
				License: matchingIssue.License,
				Identifiers: types.OssIdentifiers{
					CWE: issue.CWEs,
					CVE: issue.CVEs,
				},
				Description:       matchingIssue.Description,
				Language:          matchingIssue.Language,
				PackageManager:    matchingIssue.PackageManager,
				PackageName:       matchingIssue.PackageName,
				Name:              matchingIssue.Name,
				Version:           matchingIssue.Version,
				Exploit:           matchingIssue.Exploit,
				CVSSv3:            matchingIssue.CVSSv3,
				CvssScore:         strconv.FormatFloat(matchingIssue.CvssScore, 'f', 2, 64), // convert float64 to string with 2 decimal places
				FixedIn:           matchingIssue.FixedIn,
				From:              matchingIssue.From,
				UpgradePath:       matchingIssue.UpgradePath,
				IsPatchable:       matchingIssue.IsPatchable,
				IsUpgradable:      matchingIssue.IsUpgradable,
				ProjectName:       matchingIssue.ProjectName,
				DisplayTargetFile: matchingIssue.DisplayTargetFile,
				Details:           matchingIssue.Details,
			}
		}

		scanIssues = append(scanIssues, types.ScanIssue{
			Id:       additionalData.Key,
			Title:    additionalData.Title,
			Severity: issue.Severity.String(),
			FilePath: issue.AffectedFilePath,
			Range:    converter.ToRange(issue.Range),
			AdditionalData: types.OssIssueData{
				RuleId:  issue.ID,
				License: additionalData.License,
				Identifiers: types.OssIdentifiers{
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
				MatchingIssues:    matchingIssues,
				Lesson:            additionalData.Lesson,
			},
		})
	}

	return scanIssues
}

func (n *scanNotifier) appendIacIssues(scanIssues []types.ScanIssue, issues []snyk.Issue) []types.ScanIssue {
	for _, issue := range issues {
		additionalData, ok := issue.AdditionalData.(snyk.IaCIssueData)
		if !ok {
			continue // skip non-iac issues
		}

		scanIssues = append(scanIssues, types.ScanIssue{
			Id:       additionalData.Key,
			Title:    additionalData.Title,
			Severity: issue.Severity.String(),
			FilePath: issue.AffectedFilePath,
			Range:    converter.ToRange(issue.Range),
			AdditionalData: types.IacIssueData{
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

func (n *scanNotifier) appendCodeIssues(scanIssues []types.ScanIssue, issues []snyk.Issue) []types.ScanIssue {
	for _, issue := range issues {
		additionalData, ok := issue.AdditionalData.(snyk.CodeIssueData)
		if !ok {
			continue // skip non-code issues
		}

		exampleCommitFixes := make([]types.ExampleCommitFix, 0, len(additionalData.ExampleCommitFixes))
		for i := range additionalData.ExampleCommitFixes {
			lines := make([]types.CommitChangeLine, 0, len(additionalData.ExampleCommitFixes[i].Lines))
			for j := range additionalData.ExampleCommitFixes[i].Lines {
				lines = append(lines, types.CommitChangeLine{
					Line:       additionalData.ExampleCommitFixes[i].Lines[j].Line,
					LineNumber: additionalData.ExampleCommitFixes[i].Lines[j].LineNumber,
					LineChange: additionalData.ExampleCommitFixes[i].Lines[j].LineChange,
				})
			}
			exampleCommitFixes = append(exampleCommitFixes, types.ExampleCommitFix{
				CommitURL: additionalData.ExampleCommitFixes[i].CommitURL,
				Lines:     lines,
			})
		}

		markers := make([]types.Marker, 0, len(additionalData.Markers))
		for _, marker := range additionalData.Markers {
			positions := make([]types.MarkerPosition, 0)
			for _, pos := range marker.Pos {
				positions = append(positions, types.MarkerPosition{
					Position: types.Position{
						Rows: pos.Rows,
						Cols: pos.Cols,
					},
					File: pos.File,
				})
			}

			markers = append(markers, types.Marker{
				Msg: marker.Msg,
				Pos: positions,
			})
		}

		dataFlow := make([]types.DataflowElement, 0, len(additionalData.DataFlow))
		for _, flow := range additionalData.DataFlow {
			dataFlow = append(dataFlow, types.DataflowElement{
				Position:  flow.Position,
				FilePath:  flow.FilePath,
				FlowRange: converter.ToRange(flow.FlowRange),
				Content:   flow.Content,
			})
		}

		scanIssue := types.ScanIssue{
			Id:        additionalData.Key,
			Title:     issue.Message,
			Severity:  issue.Severity.String(),
			FilePath:  issue.AffectedFilePath,
			Range:     converter.ToRange(issue.Range),
			IsIgnored: issue.IsIgnored,
			AdditionalData: types.CodeIssueData{
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
				Details:            additionalData.Details,
			},
		}
		if scanIssue.IsIgnored {
			scanIssue.IgnoreDetails =
				types.IgnoreDetails{
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
				Issues:     nil,
			},
		)
	}
}

func (n *scanNotifier) supportedProducts() []product.Product {
	products := []product.Product{product.ProductOpenSource, product.ProductInfrastructureAsCode, product.ProductCode}
	return products
}
