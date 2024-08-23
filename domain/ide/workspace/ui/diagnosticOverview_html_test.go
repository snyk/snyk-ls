package ui

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_diagnosticOverview_normalizeFilePath(t *testing.T) {
	// Parse file path to be rendered in the UI
	tests := []struct {
		name       string
		filePath   string
		folderPath string
		expected   string
	}{
		{
			name:       "unix path",
			filePath:   "/Users/cata/git/playground/dex/server/deviceflowhandlers.go",
			folderPath: "/Users/cata/git/playground/dex",
			expected:   "dex/server/deviceflowhandlers.go",
		},
		// TODO: add Windows cases
		{
			name:       "(win) path",
			filePath:   "C:\\Users\\cata\\git\\playground\\dex\\server\\deviceflowhandlers.go",
			folderPath: "C:\\Users\\cata\\git\\playground\\dex",
			expected:   "dex\\server\\deviceflowhandlers.go",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			skipReason := "filepath is os dependent"
			prefix := "C:"

			if strings.HasPrefix(tc.folderPath, prefix) {
				testutil.OnlyOnWindows(t, skipReason)
			} else {
				testutil.NotOnWindows(t, skipReason)
			}

			actual := normalizeFilePath(tc.filePath, tc.folderPath)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func Test_diagnosticOverview_getRootNodeText(t *testing.T) {
	tests := []struct {
		name           string
		issuesByFile   snyk.IssuesByFile
		product        product.Product
		expectedOutput string
	}{
		{
			name:           "no issues",
			issuesByFile:   snyk.IssuesByFile{},
			product:        product.ProductCode,
			expectedOutput: "Code Security - No issues found",
		},
		{
			name: "One critical issue",
			issuesByFile: snyk.IssuesByFile{
				"goof/routes/index.js": []snyk.Issue{
					createTestIssue(snyk.Critical, "NoSQL Injection"),
				},
			},
			product:        product.ProductCode,
			expectedOutput: "Code Security - 1 unique issue: 1 critical",
		},
		{
			name: "Multiple issues with different severities",
			issuesByFile: snyk.IssuesByFile{
				"goof/routes/index.js": []snyk.Issue{
					createTestIssue(snyk.High, "NoSQL Injection"),
					createTestIssue(snyk.Medium, "Information Exposure"),
				},
				"goof/app.js": []snyk.Issue{
					createTestIssue(snyk.High, "Use of Hardcoded Secrets"),
					createTestIssue(snyk.Low, "Cleartext Transmission of Sensitive Information"),
				},
			},
			product:        product.ProductCode,
			expectedOutput: "Code Security - 4 unique issues: 2 high, 1 medium, 1 low",
		},
		{
			name: "Multiple issues including critical",
			issuesByFile: snyk.IssuesByFile{
				"goof/routes/index.js": []snyk.Issue{
					createTestIssue(snyk.Critical, "NoSQL Injection"),
				},
				"goof/app.js": []snyk.Issue{
					createTestIssue(snyk.High, "Hardcoded Secret"),
					createTestIssue(snyk.Medium, "Information Exposure"),
					createTestIssue(snyk.Low, "Use of Hardcoded Credentials"),
				},
			},
			product:        product.ProductCode,
			expectedOutput: "Code Security - 4 unique issues: 1 critical, 1 high, 1 medium, 1 low",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			output := getRootNodeText(tc.issuesByFile, tc.product)
			assert.Equal(t, tc.expectedOutput, output)
		})
	}
}

func Test_getFileNodes_diagnosticsAreSortedBySeverity(t *testing.T) {
	tests := []struct {
		name          string
		issuesByFile  snyk.IssuesByFile
		expectedOrder []string
	}{
		{
			name: "Sort issues by severity within a file",
			issuesByFile: snyk.IssuesByFile{
				"dex.yaml": []snyk.Issue{
					createTestIssue(snyk.Low, "(L) Container has no CPU limit"),
					createTestIssue(snyk.High, "(H) Role or ClusterRole with too wide permissions"),
					createTestIssue(snyk.Medium, "(M) Container is running without privilege escalation control"),
					createTestIssue(snyk.Critical, "(C) Container or Pod is running without root user control"),
				},
			},
			expectedOrder: []string{
				"(C) Container or Pod is running without root user control",
				"(H) Role or ClusterRole with too wide permissions",
				"(M) Container is running without privilege escalation control",
				"(L) Container has no CPU limit",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Assuming getFileNodes is the function that sorts issues within files
			fileNodes := getFileNodes(tc.issuesByFile, "")

			var actualOrder []string
			for _, issues := range fileNodes {
				for _, issue := range issues {
					actualOrder = append(actualOrder, string(issue.Text))
				}
			}

			assert.Equal(t, tc.expectedOrder, actualOrder)
		})
	}
}

func Test_sortIssuesBySeverity(t *testing.T) {
	issues := []snyk.Issue{
		createTestIssue(snyk.Low, "(L) Container has no CPU limit"),
		createTestIssue(snyk.High, "(H) Role or ClusterRole with too wide permissions"),
		createTestIssue(snyk.Medium, "(M) Container is running without privilege escalation control"),
		createTestIssue(snyk.Critical, "(C) Container or Pod is running without root user control"),
	}

	expectedOrder := []string{
		"(C) Container or Pod is running without root user control",
		"(H) Role or ClusterRole with too wide permissions",
		"(M) Container is running without privilege escalation control",
		"(L) Container has no CPU limit",
	}

	sortedIssues := sortIssuesBySeverity(issues)
	var actualOrder []string
	for _, issue := range sortedIssues {
		actualOrder = append(actualOrder, issue.AdditionalData.GetTitle())
	}

	assert.Equal(t, expectedOrder, actualOrder)
}

func createTestIssue(severity snyk.Severity, title string) snyk.Issue {
	return snyk.Issue{
		ID:       uuid.NewString(),
		Severity: severity,
		AdditionalData: mockAddData{
			title: title,
			key:   uuid.NewString(),
		},
	}
}
