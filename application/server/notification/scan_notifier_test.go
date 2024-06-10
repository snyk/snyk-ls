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

package notification_test

import (
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	notification2 "github.com/snyk/snyk-ls/application/server/notification"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/snyk"
	lsp2 "github.com/snyk/snyk-ls/internal/lsp"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
)

type sendMessageTestCase struct {
	name           string
	act            func(scanNotifier snyk.ScanNotifier)
	expectedStatus lsp2.ScanStatus
}

func Test_SendMessage(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetSnykCodeEnabled(true)

	const folderPath = "/test/folderPath"

	tests := []sendMessageTestCase{
		{
			name: "SendInProgressMessage",
			act: func(scanNotifier snyk.ScanNotifier) {
				scanNotifier.SendInProgress(folderPath)
			},
			expectedStatus: lsp2.InProgress,
		},
		{
			name: "SendSuccessMessage",
			act: func(scanNotifier snyk.ScanNotifier) {
				scanNotifier.SendSuccess(product.ProductCode, folderPath, []snyk.Issue{})
			},
			expectedStatus: lsp2.Success,
		},
		{
			name: "SendErrorMessage",
			act: func(scanNotifier snyk.ScanNotifier) {
				scanNotifier.SendError(product.ProductCode, folderPath)
			},
			expectedStatus: lsp2.ErrorStatus,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expectedProduct := "code"
			mockNotifier := notification.NewMockNotifier()
			scanNotifier, _ := notification2.NewScanNotifier(c, mockNotifier)

			// Act - run the test
			test.act(scanNotifier)

			// Assert - search through all the messages for the expected message
			for _, msg := range mockNotifier.SentMessages() {
				if containsMatchingMessage(t, msg, test, expectedProduct, folderPath) {
					return
				}
			}
			assert.Fail(t, "Scan message was not sent")
		})
	}
}

func Test_SendSuccess_SendsForAllEnabledProducts(t *testing.T) {
	c := testutil.UnitTest(t)

	mockNotifier := notification.NewMockNotifier()
	scanNotifier, _ := notification2.NewScanNotifier(c, mockNotifier)

	const folderPath = "/test/iac/folderPath"

	testRange := snyk.Range{
		Start: snyk.Position{
			Line:      1,
			Character: 1,
		},
		End: snyk.Position{
			Line:      1,
			Character: 2,
		},
	}
	lspTestRange := converter.ToRange(testRange)

	expectedIacIssue := []lsp2.ScanIssue{
		{
			Id:       "098f6bcd4621d373cade4e832627b4f6",
			Title:    "iacTitle",
			Severity: "critical",
			FilePath: "iacAffectedFilePath",
			Range:    lspTestRange,
			AdditionalData: lsp2.IacIssueData{
				PublicId:      "iacID",
				Documentation: "iacDocumentation",
				LineNumber:    1,
				Issue:         "iacIssue",
				Impact:        "iacImpact",
				Path:          []string{"iacPath"},
			},
		},
	}

	expectedCodeIssue := []lsp2.ScanIssue{
		{
			Id:       "5a105e8b9d40e1329780d62ea2265d8a",
			Title:    "codeMessage",
			Severity: "low",
			FilePath: "codeAffectedFilePath",
			Range:    lspTestRange,
			AdditionalData: lsp2.CodeIssueData{
				Message:            "codeMessage",
				Rule:               "codeRule",
				RuleId:             "codeRuleID",
				RepoDatasetSize:    2,
				ExampleCommitFixes: []lsp2.ExampleCommitFix{},
				CWE:                []string{},
				IsSecurityType:     false,
				Text:               "codeText",
				Cols:               lsp2.Point{1, 1},
				Rows:               lsp2.Point{1, 1},
				Markers:            []lsp2.Marker{},
				PriorityScore:      880,
				HasAIFix:           true,
				DataFlow: []lsp2.DataflowElement{
					{FilePath: "testFile", FlowRange: converter.ToRange(testRange), Content: "testContent"},
				},
			},
		},
	}

	scanIssues := []snyk.Issue{
		{ // IaC issue
			ID:                  "iacID",
			Severity:            snyk.Critical,
			IssueType:           1,
			Range:               testRange,
			Message:             "iacMessage",
			FormattedMessage:    "iacFormattedMessage",
			AffectedFilePath:    "iacAffectedFilePath",
			Product:             product.ProductInfrastructureAsCode,
			References:          []snyk.Reference{},
			IssueDescriptionURL: &url.URL{},
			CodeActions:         []snyk.CodeAction{},
			CodelensCommands:    []snyk.CommandData{},
			AdditionalData: snyk.IaCIssueData{
				Key:           "098f6bcd4621d373cade4e832627b4f6",
				Title:         "iacTitle",
				PublicId:      "iacID",
				Documentation: "iacDocumentation",
				LineNumber:    1,
				Issue:         "iacIssue",
				Impact:        "iacImpact",
				Path:          []string{"iacPath"},
			},
		},
		{ // Code issue
			ID:                  "codeID",
			Severity:            snyk.Low,
			IssueType:           1,
			Range:               testRange,
			Message:             "codeMessage",
			FormattedMessage:    "codeFormattedMessage",
			AffectedFilePath:    "codeAffectedFilePath",
			Product:             product.ProductCode,
			References:          []snyk.Reference{},
			IssueDescriptionURL: &url.URL{},
			CodeActions:         []snyk.CodeAction{},
			CodelensCommands:    []snyk.CommandData{},
			AdditionalData: snyk.CodeIssueData{
				Key:                "5a105e8b9d40e1329780d62ea2265d8a",
				Message:            "codeMessage",
				Rule:               "codeRule",
				RuleId:             "codeRuleID",
				RepoDatasetSize:    2,
				ExampleCommitFixes: []snyk.ExampleCommitFix{},
				CWE:                []string{},
				IsSecurityType:     false,
				Text:               "codeText",
				Cols:               snyk.CodePoint{1, 1},
				Rows:               snyk.CodePoint{1, 1},
				Markers:            []snyk.Marker{},
				PriorityScore:      880,
				HasAIFix:           true,
				DataFlow: []snyk.DataFlowElement{
					{FilePath: "testFile", FlowRange: testRange, Content: "testContent"},
				},
			},
		},
	}

	// Act - run the test
	scanNotifier.SendSuccessForAllProducts(folderPath, scanIssues)

	// Assert - check the messages matches the expected message for each product
	for _, msg := range mockNotifier.SentMessages() {
		if msg.(lsp2.SnykScanParams).Product == "code" {
			actualCodeIssue := msg.(lsp2.SnykScanParams).Issues
			assert.Equal(t, expectedCodeIssue, actualCodeIssue)
			return
		}
		if msg.(lsp2.SnykScanParams).Product == "iac" {
			actualIacIssue := msg.(lsp2.SnykScanParams).Issues
			assert.Equal(t, expectedIacIssue, actualIacIssue)
			return
		}
	}
}

func Test_SendSuccess_SendsForOpenSource(t *testing.T) {
	c := testutil.UnitTest(t)

	mockNotifier := notification.NewMockNotifier()
	scanNotifier, _ := notification2.NewScanNotifier(c, mockNotifier)

	const folderPath = "/test/oss/folderPath"

	r := snyk.Range{
		Start: snyk.Position{
			Line:      1,
			Character: 1,
		},
		End: snyk.Position{
			Line:      1,
			Character: 2,
		},
	}
	lspTestRange := converter.ToRange(r)

	expectedUIScanIssue := []lsp2.ScanIssue{
		{
			Id:       "OSS Key",
			Title:    "OSS Title",
			Severity: "critical",
			FilePath: "/test/oss/folderPath/ossAffectedFilePath",
			Range:    lspTestRange,
			AdditionalData: lsp2.OssIssueData{
				RuleId:  "SNYK-JS-BABELTRAVERSE-5962463",
				License: "OSS License",
				Identifiers: lsp2.OssIdentifiers{
					CWE: []string{"CWE-184"},
					CVE: []string{"CVE-2023-45133"},
				},
				Description:    "OSS Description",
				Language:       "js",
				PackageManager: "OSS PackageManager",
				PackageName:    "OSS PackageName",
				Name:           "OSS Name",
				Version:        "OSS Version",
				Exploit:        "OSS Exploit",
				CVSSv3:         "OSS CVSSv3",
				CvssScore:      "9.90",
				FixedIn:        []string{},
				From:           []string{"babel/transverse@6.26.0"},
				UpgradePath: []any{
					true,
					"babel-traverse@6.26.0",
				},
				IsPatchable:       false,
				IsUpgradable:      false,
				ProjectName:       "OSS ProjectName",
				DisplayTargetFile: "OSS DisplayTargetFile",
				Details:           "",
				MatchingIssues:    []lsp2.OssIssueData{},
				Lesson:            "test",
			},
		},
	}

	issues := []snyk.Issue{
		{ // OSS issue
			ID:                  "SNYK-JS-BABELTRAVERSE-5962463",
			Severity:            snyk.Critical,
			IssueType:           1,
			Range:               r,
			Message:             "Incomplete List of Disallowed Inputs",
			FormattedMessage:    "Incomplete List of Disallowed Inputs",
			AffectedFilePath:    "/test/oss/folderPath/ossAffectedFilePath",
			Product:             product.ProductOpenSource,
			References:          []snyk.Reference{},
			IssueDescriptionURL: &url.URL{},
			CodeActions:         []snyk.CodeAction{},
			CodelensCommands:    []snyk.CommandData{},
			Ecosystem:           "OSS Ecosystem",
			CWEs:                []string{"CWE-184"},
			CVEs:                []string{"CVE-2023-45133"},
			AdditionalData: snyk.OssIssueData{
				Key:            "OSS Key",
				Title:          "OSS Title",
				Name:           "OSS Name",
				LineNumber:     1,
				Description:    "OSS Description",
				References:     []snyk.Reference{},
				Version:        "OSS Version",
				License:        "OSS License",
				PackageManager: "OSS PackageManager",
				PackageName:    "OSS PackageName",
				From:           []string{"babel/transverse@6.26.0"},
				FixedIn:        []string{},
				UpgradePath: []any{
					true,
					"babel-traverse@6.26.0",
				},
				IsUpgradable:      false,
				CVSSv3:            "OSS CVSSv3",
				CvssScore:         9.9,
				Exploit:           "OSS Exploit",
				IsPatchable:       false,
				ProjectName:       "OSS ProjectName",
				DisplayTargetFile: "OSS DisplayTargetFile",
				Language:          "js",
				Details:           "",
				Lesson:            "test",
			},
		},
	}

	// Act - run the test
	scanNotifier.SendSuccess(product.ProductOpenSource, folderPath, issues)

	// Assert - check that there are messages sent
	assert.NotEmpty(t, mockNotifier.SentMessages())

	// Assert - check the messages matches the expected message for each product
	for _, msg := range mockNotifier.SentMessages() {
		actualUIOssIssue := msg.(lsp2.SnykScanParams).Issues
		assert.Equal(t, expectedUIScanIssue, actualUIOssIssue)
		return
	}
}

func Test_SendSuccess_SendsForSnykCode(t *testing.T) {
	c := testutil.UnitTest(t)

	mockNotifier := notification.NewMockNotifier()
	scanNotifier, _ := notification2.NewScanNotifier(c, mockNotifier)

	const folderPath = "/test/iac/folderPath"
	r := snyk.Range{
		Start: snyk.Position{
			Line:      1,
			Character: 1,
		},
		End: snyk.Position{
			Line:      1,
			Character: 2,
		},
	}
	lspTestRange := converter.ToRange(r)

	expectedCodeIssue := []lsp2.ScanIssue{
		{
			Id:       "5a105e8b9d40e1329780d62ea2265d8a",
			Title:    "codeMessage",
			Severity: "low",
			FilePath: "codeAffectedFilePath",
			Range:    lspTestRange,
			AdditionalData: lsp2.CodeIssueData{
				Message:            "codeMessage",
				Rule:               "codeRule",
				RuleId:             "codeRuleID",
				RepoDatasetSize:    2,
				ExampleCommitFixes: []lsp2.ExampleCommitFix{},
				CWE:                []string{},
				IsSecurityType:     false,
				Text:               "codeText",
				Cols:               lsp2.Point{1, 1},
				Rows:               lsp2.Point{1, 1},
				Markers:            []lsp2.Marker{},
				DataFlow: []lsp2.DataflowElement{
					{FilePath: "testFile", FlowRange: converter.ToRange(r), Content: "testContent"},
				},
			},
		},
	}

	scanIssues := []snyk.Issue{
		{ // Code issue
			ID:                  "codeID",
			Severity:            snyk.Low,
			IssueType:           1,
			Range:               r,
			Message:             "codeMessage",
			FormattedMessage:    "codeFormattedMessage",
			AffectedFilePath:    "codeAffectedFilePath",
			Product:             product.ProductCode,
			References:          []snyk.Reference{},
			IssueDescriptionURL: &url.URL{},
			CodeActions:         []snyk.CodeAction{},
			CodelensCommands:    []snyk.CommandData{},
			AdditionalData: snyk.CodeIssueData{
				Key:                "5a105e8b9d40e1329780d62ea2265d8a",
				Message:            "codeMessage",
				Rule:               "codeRule",
				RuleId:             "codeRuleID",
				RepoDatasetSize:    2,
				ExampleCommitFixes: []snyk.ExampleCommitFix{},
				CWE:                []string{},
				IsSecurityType:     false,
				Text:               "codeText",
				Cols:               snyk.CodePoint{1, 1},
				Rows:               snyk.CodePoint{1, 1},
				Markers:            []snyk.Marker{},
				DataFlow: []snyk.DataFlowElement{
					{FilePath: "testFile", FlowRange: r, Content: "testContent"},
				},
			},
		},
	}

	// Act - run the test
	scanNotifier.SendSuccess(product.ProductCode, folderPath, scanIssues)

	// Assert - check the messages matches the expected message for each product
	for _, msg := range mockNotifier.SentMessages() {
		actualCodeIssue := msg.(lsp2.SnykScanParams).Issues
		assert.Equal(t, expectedCodeIssue, actualCodeIssue)
		return
	}
}

func Test_SendSuccess_SendsForSnykCode_WithIgnores(t *testing.T) {
	c := testutil.UnitTest(t)

	mockNotifier := notification.NewMockNotifier()
	scanNotifier, _ := notification2.NewScanNotifier(c, mockNotifier)

	const folderPath = "/test/iac/folderPath"
	r := snyk.Range{
		Start: snyk.Position{
			Line:      1,
			Character: 1,
		},
		End: snyk.Position{
			Line:      1,
			Character: 2,
		},
	}
	lspTestRange := converter.ToRange(r)

	ignoredOn := time.Now()
	expectedCodeIssue := []lsp2.ScanIssue{
		{
			Id:        "5a105e8b9d40e1329780d62ea2265d8a",
			Title:     "codeMessage",
			Severity:  "low",
			FilePath:  "codeAffectedFilePath",
			Range:     lspTestRange,
			IsIgnored: true,
			IgnoreDetails: lsp2.IgnoreDetails{
				Category:   "category",
				Reason:     "reason",
				Expiration: "expiration",
				IgnoredOn:  ignoredOn,
				IgnoredBy:  "ignoredBy",
			}, AdditionalData: lsp2.CodeIssueData{
				Message:            "codeMessage",
				Rule:               "codeRule",
				RuleId:             "codeRuleID",
				RepoDatasetSize:    2,
				ExampleCommitFixes: []lsp2.ExampleCommitFix{},
				CWE:                []string{},
				IsSecurityType:     false,
				Text:               "codeText",
				Cols:               lsp2.Point{1, 1},
				Rows:               lsp2.Point{1, 1},
				Markers:            []lsp2.Marker{},
				DataFlow: []lsp2.DataflowElement{
					{FilePath: "testFile", FlowRange: converter.ToRange(r), Content: "testContent"},
				},
				Details: "<!-- Data Flow -->\n <span class=\"data-flow-filepath\">testFile/data-subject.service.ts:27</span>\n\t\t",
			},
		},
	}

	scanIssues := []snyk.Issue{
		{ // Code issue
			ID:        "codeID",
			Severity:  snyk.Low,
			IssueType: 1,
			Range:     r,
			Message:   "codeMessage",
			IsIgnored: true,
			IgnoreDetails: &snyk.IgnoreDetails{
				Category:   "category",
				Reason:     "reason",
				Expiration: "expiration",
				IgnoredOn:  ignoredOn,
				IgnoredBy:  "ignoredBy",
			},
			FormattedMessage:    "codeFormattedMessage",
			AffectedFilePath:    "codeAffectedFilePath",
			Product:             product.ProductCode,
			References:          []snyk.Reference{},
			IssueDescriptionURL: &url.URL{},
			CodeActions:         []snyk.CodeAction{},
			CodelensCommands:    []snyk.CommandData{},
			AdditionalData: snyk.CodeIssueData{
				Key:                "5a105e8b9d40e1329780d62ea2265d8a",
				Message:            "codeMessage",
				Rule:               "codeRule",
				RuleId:             "codeRuleID",
				RepoDatasetSize:    2,
				ExampleCommitFixes: []snyk.ExampleCommitFix{},
				CWE:                []string{},
				IsSecurityType:     false,
				Text:               "codeText",
				Cols:               snyk.CodePoint{1, 1},
				Rows:               snyk.CodePoint{1, 1},
				Markers:            []snyk.Marker{},
				DataFlow: []snyk.DataFlowElement{
					{FilePath: "testFile", FlowRange: r, Content: "testContent"},
				},
				Details: "<!-- Data Flow -->\n <span class=\"data-flow-filepath\">testFile/data-subject.service.ts:27</span>\n\t\t",
			},
		},
	}

	// Act - run the test
	scanNotifier.SendSuccess(product.ProductCode, folderPath, scanIssues)

	// Assert - check the messages matches the expected message for each product
	for _, msg := range mockNotifier.SentMessages() {
		actualCodeIssue := msg.(lsp2.SnykScanParams).Issues
		assert.Equal(t, expectedCodeIssue, actualCodeIssue)
		return
	}
}

func Test_SendSuccess_SendsForAllSnykIac(t *testing.T) {
	c := testutil.UnitTest(t)

	mockNotifier := notification.NewMockNotifier()
	scanNotifier, _ := notification2.NewScanNotifier(c, mockNotifier)

	const folderPath = "/test/iac/folderPath"
	r := snyk.Range{
		Start: snyk.Position{
			Line:      1,
			Character: 1,
		},
		End: snyk.Position{
			Line:      1,
			Character: 2,
		},
	}
	lspTestRange := converter.ToRange(r)

	// expected message uses lsp2.ScanIssue && lsp2.CodeIssueData
	expectedIacIssue := []lsp2.ScanIssue{
		{
			Id:       "098f6bcd4621d373cade4e832627b4f6",
			Title:    "iacTitle",
			Severity: "critical",
			FilePath: "/test/iac/folderPath/iacAffectedFilePath",
			Range:    lspTestRange,
			AdditionalData: lsp2.IacIssueData{
				PublicId:      "iacID",
				Documentation: "iacDocumentation",
				LineNumber:    1,
				Issue:         "iacIssue",
				Impact:        "iacImpact",
				Path:          []string{"iacPath"},
			},
		},
	}

	scanIssues := []snyk.Issue{
		{ // IaC issue
			ID:                  "iacID",
			Severity:            snyk.Critical,
			IssueType:           1,
			Range:               r,
			Message:             "iacMessage",
			FormattedMessage:    "iacFormattedMessage",
			AffectedFilePath:    "/test/iac/folderPath/iacAffectedFilePath",
			Product:             product.ProductInfrastructureAsCode,
			References:          []snyk.Reference{},
			IssueDescriptionURL: &url.URL{},
			CodeActions:         []snyk.CodeAction{},
			CodelensCommands:    []snyk.CommandData{},
			AdditionalData: snyk.IaCIssueData{
				Key:           "098f6bcd4621d373cade4e832627b4f6",
				Title:         "iacTitle",
				PublicId:      "iacID",
				Documentation: "iacDocumentation",
				LineNumber:    1,
				Issue:         "iacIssue",
				Impact:        "iacImpact",
				Path:          []string{"iacPath"},
			},
		},
	}

	// Act - run the test
	scanNotifier.SendSuccess(product.ProductInfrastructureAsCode, folderPath, scanIssues)

	// Assert - check the messages matches the expected message for each product
	for _, msg := range mockNotifier.SentMessages() {
		actualIacIssue := msg.(lsp2.SnykScanParams).Issues
		assert.Equal(t, expectedIacIssue, actualIacIssue)
		return
	}
}

func Test_NewScanNotifier_NilNotifier_Errors(t *testing.T) {
	c := testutil.UnitTest(t)
	scanNotifier, err := notification2.NewScanNotifier(c, nil)
	assert.Error(t, err)
	assert.Nil(t, scanNotifier)
}

func Test_SendInProgress_SendsForAllEnabledProducts(t *testing.T) {
	c := testutil.UnitTest(t)
	t.Run("snyk code enabled via general flag", func(t *testing.T) {
		c.SetSnykIacEnabled(true)
		c.SetSnykOssEnabled(true)
		c.SetSnykCodeEnabled(true)

		// Arrange
		mockNotifier := notification.NewMockNotifier()
		scanNotifier, _ := notification2.NewScanNotifier(c, mockNotifier)

		// Act
		scanNotifier.SendInProgress("/test/folderPath")

		// Assert
		assert.Equal(t, 3, len(mockNotifier.SentMessages()))
	})
	t.Run("snyk code enabled via security", func(t *testing.T) {
		c.SetSnykIacEnabled(true)
		c.SetSnykOssEnabled(true)
		c.SetSnykCodeEnabled(false)
		c.EnableSnykCodeSecurity(true)

		// Arrange
		mockNotifier := notification.NewMockNotifier()
		scanNotifier, _ := notification2.NewScanNotifier(c, mockNotifier)

		// Act
		scanNotifier.SendInProgress("/test/folderPath")

		// Assert
		assert.Equal(t, 3, len(mockNotifier.SentMessages()))
	})
	t.Run("snyk code enabled via quality", func(t *testing.T) {
		c.SetSnykIacEnabled(true)
		c.SetSnykOssEnabled(true)
		c.SetSnykCodeEnabled(false)
		c.EnableSnykCodeQuality(true)

		// Arrange
		mockNotifier := notification.NewMockNotifier()
		scanNotifier, _ := notification2.NewScanNotifier(c, mockNotifier)

		// Act
		scanNotifier.SendInProgress("/test/folderPath")

		// Assert
		assert.Equal(t, 3, len(mockNotifier.SentMessages()))
	})
}

func containsMatchingMessage(t *testing.T,
	msg any,
	testCase sendMessageTestCase,
	expectedProduct string,
	folderPath string,
) bool {
	t.Helper()
	scanMessage, ok := msg.(lsp2.SnykScanParams)
	if ok &&
		scanMessage.Status == testCase.expectedStatus &&
		scanMessage.Product == expectedProduct &&
		scanMessage.FolderPath == folderPath {
		return true
	}
	return false
}
