package notification_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	lsp2 "github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_SendInProgressMessage_InProgressMessageSent(t *testing.T) {
	testutil.UnitTest(t)
	expectedProductName := "foo"
	notifier := notification.NewNotifier(expectedProductName)
	messageReceived := false
	notification.CreateListener(func(params any) {
		msg, ok := params.(lsp2.SnykScanParams)
		if ok && msg.Status == lsp2.InProgress && msg.Product == expectedProductName {
			messageReceived = true
		}
	})

	notifier.SendInProgress("/test/folderPath")

	assert.Eventually(t, func() bool { return messageReceived }, 3*time.Second, 50*time.Millisecond)
}

func Test_SendSuccessMessage_SuccessMessageSent(t *testing.T) {
	testutil.UnitTest(t)
	expectedProductName := "foo"
	notifier := notification.NewNotifier(expectedProductName)
	messageReceived := false
	notification.CreateListener(func(params any) {
		msg, ok := params.(lsp2.SnykScanParams)
		if ok && msg.Status == lsp2.Success && msg.Product == expectedProductName {
			messageReceived = true
		}
	})

	notifier.SendSuccess("/test/folderPath")

	assert.Eventually(t, func() bool { return messageReceived }, 3*time.Second, 50*time.Millisecond)
}

func Test_SendErrorMessage_ErrorMessageReceived(t *testing.T) {
	testutil.UnitTest(t)
	expectedProductName := "foo"
	notifier := notification.NewNotifier(expectedProductName)
	messageReceived := false
	notification.CreateListener(func(params any) {
		msg, ok := params.(lsp2.SnykScanParams)
		if ok && msg.Status == lsp2.ErrorStatus && msg.Product == expectedProductName {
			messageReceived = true
		}
	})

	notifier.SendError("/test/folderPath")

	assert.Eventually(t, func() bool { return messageReceived }, 3*time.Second, 50*time.Millisecond)
}

func Test_AllMessages(t *testing.T) {

}
