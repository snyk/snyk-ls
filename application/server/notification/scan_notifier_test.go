package notification_test

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	notification2 "github.com/snyk/snyk-ls/application/server/notification"
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
	testutil.UnitTest(t)

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
			scanNotifier, _ := notification2.NewScanNotifier(mockNotifier)

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
	testutil.UnitTest(t)

	mockNotifier := notification.NewMockNotifier()
	scanNotifier, _ := notification2.NewScanNotifier(mockNotifier)

	const folderPath = "/test/iac/folderPath"

	// expected message uses lsp2.ScanIssue && lsp2.CodeIssueData
	expectedIacIssue := []lsp2.ScanIssue{
		{
			Id:       "098f6bcd4621d373cade4e832627b4f6",
			Title:    "iacTitle",
			Severity: "critical",
			FilePath: "iacAffectedFilePath",
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
			},
		},
	}

	scanIssues := []snyk.Issue{
		{ // IaC issue
			ID:        "iacID",
			Severity:  snyk.Critical,
			IssueType: 1,
			Range: snyk.Range{
				Start: snyk.Position{
					Line:      1,
					Character: 1,
				},
				End: snyk.Position{
					Line:      1,
					Character: 2,
				},
			},
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
			ID:        "codeID",
			Severity:  snyk.Low,
			IssueType: 1,
			Range: snyk.Range{
				Start: snyk.Position{
					Line:      1,
					Character: 1,
				},
				End: snyk.Position{
					Line:      1,
					Character: 2,
				},
			},
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
	testutil.UnitTest(t)

	mockNotifier := notification.NewMockNotifier()
	scanNotifier, _ := notification2.NewScanNotifier(mockNotifier)

	const folderPath = "/test/oss/folderPath"

	expectedUIScanIssue := []lsp2.ScanIssue{
		{
			Id:       "OSS Key",
			Title:    "OSS Title",
			Severity: "critical",
			FilePath: "ossAffectedFilePath",
			AdditionalData: lsp2.OssIssueData{
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
			},
		},
	}

	issues := []snyk.Issue{
		{ // OSS issue
			ID:        "SNYK-JS-BABELTRAVERSE-5962463",
			Severity:  snyk.Critical,
			IssueType: 1,
			Range: snyk.Range{
				Start: snyk.Position{
					Line:      1,
					Character: 1,
				},
				End: snyk.Position{
					Line:      1,
					Character: 2,
				},
			},
			Message:             "Incomplete List of Disallowed Inputs",
			FormattedMessage:    "Incomplete List of Disallowed Inputs",
			AffectedFilePath:    "ossAffectedFilePath",
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
				GHSA:           []string{"GHSA-123"},
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
	testutil.UnitTest(t)

	mockNotifier := notification.NewMockNotifier()
	scanNotifier, _ := notification2.NewScanNotifier(mockNotifier)

	const folderPath = "/test/iac/folderPath"

	expectedCodeIssue := []lsp2.ScanIssue{
		{
			Id:       "5a105e8b9d40e1329780d62ea2265d8a",
			Title:    "codeMessage",
			Severity: "low",
			FilePath: "codeAffectedFilePath",
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
			},
		},
	}

	scanIssues := []snyk.Issue{
		{ // Code issue
			ID:        "codeID",
			Severity:  snyk.Low,
			IssueType: 1,
			Range: snyk.Range{
				Start: snyk.Position{
					Line:      1,
					Character: 1,
				},
				End: snyk.Position{
					Line:      1,
					Character: 2,
				},
			},
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
	testutil.UnitTest(t)

	mockNotifier := notification.NewMockNotifier()
	scanNotifier, _ := notification2.NewScanNotifier(mockNotifier)

	const folderPath = "/test/iac/folderPath"

	// expected message uses lsp2.ScanIssue && lsp2.CodeIssueData
	expectedIacIssue := []lsp2.ScanIssue{
		{
			Id:       "098f6bcd4621d373cade4e832627b4f6",
			Title:    "iacTitle",
			Severity: "critical",
			FilePath: "iacAffectedFilePath",
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
			ID:        "iacID",
			Severity:  snyk.Critical,
			IssueType: 1,
			Range: snyk.Range{
				Start: snyk.Position{
					Line:      1,
					Character: 1,
				},
				End: snyk.Position{
					Line:      1,
					Character: 2,
				},
			},
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

	scanNotifier, err := notification2.NewScanNotifier(nil)
	assert.Error(t, err)
	assert.Nil(t, scanNotifier)
}

func Test_SendInProgress_SendsForAllEnabledProducts(t *testing.T) {
	testutil.UnitTest(t)

	// Arrange
	mockNotifier := notification.NewMockNotifier()
	scanNotifier, _ := notification2.NewScanNotifier(mockNotifier)

	// Act
	scanNotifier.SendInProgress("/test/folderPath")

	// Assert
	assert.Equal(t, 2, len(mockNotifier.SentMessages()))
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
