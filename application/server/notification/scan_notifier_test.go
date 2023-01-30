package notification_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	lsp2 "github.com/snyk/snyk-ls/application/server/lsp"
	notification2 "github.com/snyk/snyk-ls/application/server/notification"
	"github.com/snyk/snyk-ls/domain/snyk"
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
				scanNotifier.SendSuccess(folderPath, []snyk.Issue{})
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

func Test_NewScanNotifier_NilNotifier_Errors(t *testing.T) {
	t.Parallel()
	scanNotifier, err := notification2.NewScanNotifier(nil)
	assert.Error(t, err)
	assert.Nil(t, scanNotifier)
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
