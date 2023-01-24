package notification_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	lsp2 "github.com/snyk/snyk-ls/application/server/lsp"
	notification2 "github.com/snyk/snyk-ls/application/server/notification"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_SendMessage(t *testing.T) {
	testutil.UnitTest(t)

	folderPath := "/test/folderPath"

	tests := []struct {
		name           string
		act            func(scanNotifier snyk.ScanNotifier)
		expectedStatus lsp2.ScanStatus
	}{
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
				scanNotifier.SendSuccess(folderPath)
			},
			expectedStatus: lsp2.Success,
		},
		{
			name: "SendErrorMessage",
			act: func(scanNotifier snyk.ScanNotifier) {
				scanNotifier.SendError(folderPath)
			},
			expectedStatus: lsp2.ErrorStatus,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expectedProduct := "foo"
			mockNotifier := notification.NewMockNotifier()
			scanNotifier, _ := notification2.NewScanNotifier(mockNotifier, expectedProduct)

			test.act(scanNotifier)

			for _, msg := range mockNotifier.SentMessages() {
				scanMessage, ok := msg.(lsp2.SnykScanParams)
				if ok &&
					scanMessage.Status == test.expectedStatus &&
					scanMessage.Product == expectedProduct &&
					scanMessage.FolderPath == folderPath {
					return
				}
			}
			assert.Fail(t, "Scan message was not sent")
		})
	}
}

func Test_NewScanNotifier_EmptyProductName_Errors(t *testing.T) {
	t.Parallel()
	scanNotifier, err := notification2.NewScanNotifier(notification.NewMockNotifier(), "")
	assert.Error(t, err)
	assert.Nil(t, scanNotifier)
}

func Test_NewScanNotifier_NilNotifier_Errors(t *testing.T) {
	t.Parallel()
	scanNotifier, err := notification2.NewScanNotifier(nil, "code")
	assert.Error(t, err)
	assert.Nil(t, scanNotifier)
}
