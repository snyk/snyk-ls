package notification_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	lsp2 "github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/testutil"
)

const productName = "foo"
const folderPath = "/test/folderPath"

func Test_SendInProgressMessage_InProgressMessageSent(t *testing.T) {
	// Arrange
	testutil.UnitTest(t)
	expectedProductName := productName
	mockNotifier := notification.NewMockNotifier()
	scanNotifier := notification.NewScanNotifier(mockNotifier, expectedProductName)

	// Act
	scanNotifier.SendInProgress(folderPath)

	// Assert
	for _, msg := range mockNotifier.GetSentMessages() {
		scanMessage, ok := msg.(lsp2.SnykScanParams)
		if ok && scanMessage.Status == lsp2.InProgress && scanMessage.Product == expectedProductName {
			return
		}
	}
	assert.Fail(t, "Scan message was not sent")
}

func Test_SendSuccessMessage_SuccessMessageSent(t *testing.T) {
	// Arrange
	testutil.UnitTest(t)
	expectedProductName := productName
	mockNotifier := notification.NewMockNotifier()
	scanNotifier := notification.NewScanNotifier(mockNotifier, expectedProductName)

	// Act
	scanNotifier.SendSuccess(folderPath)

	// Assert
	for _, msg := range mockNotifier.GetSentMessages() {
		scanMessage, ok := msg.(lsp2.SnykScanParams)
		if ok && scanMessage.Status == lsp2.Success && scanMessage.Product == expectedProductName {
			return
		}
	}
	assert.Fail(t, "Scan message was not sent")
}

func Test_SendErrorMessage_ErrorMessageReceived(t *testing.T) {
	// Arrange
	testutil.UnitTest(t)
	expectedProductName := productName
	mockNotifier := notification.NewMockNotifier()
	scanNotifier := notification.NewScanNotifier(mockNotifier, expectedProductName)

	// Act
	scanNotifier.SendError(folderPath)

	// Assert
	for _, msg := range mockNotifier.GetSentMessages() {
		scanMessage, ok := msg.(lsp2.SnykScanParams)
		if ok && scanMessage.Status == lsp2.ErrorStatus && scanMessage.Product == expectedProductName {
			return
		}
	}
	assert.Fail(t, "Scan message was not sent")
}
