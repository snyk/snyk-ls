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
	"testing"

	"github.com/stretchr/testify/assert"

	notification2 "github.com/snyk/snyk-ls/application/server/notification"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

type sendMessageTestCase struct {
	name           string
	act            func(scanNotifier scanner.ScanNotifier)
	expectedStatus types.ScanStatus
}

func Test_SendMessage(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetSnykCodeEnabled(true)

	const folderPath = "/test/folderPath"

	tests := []sendMessageTestCase{
		{
			name: "SendInProgressMessage",
			act: func(scanNotifier scanner.ScanNotifier) {
				scanNotifier.SendInProgress(folderPath)
			},
			expectedStatus: types.InProgress,
		},
		{
			name: "SendSuccessMessage",
			act: func(scanNotifier scanner.ScanNotifier) {
				scanNotifier.SendSuccess(product.ProductCode, folderPath)
			},
			expectedStatus: types.Success,
		},
		{
			name: "SendErrorMessage",
			act: func(scanNotifier scanner.ScanNotifier) {
				scanNotifier.SendError(product.ProductCode, folderPath, "")
			},
			expectedStatus: types.ErrorStatus,
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

	// Act - run the test
	scanNotifier.SendSuccessForAllProducts(folderPath)

	// Assert
	for _, msg := range mockNotifier.SentMessages() {
		scanParam := msg.(types.SnykScanParams)
		assert.Equal(t, types.Success, scanParam.Status)
		assert.Equal(t, folderPath, scanParam.FolderPath)
	}
}

func Test_SendSuccess_SendsForOpenSource(t *testing.T) {
	c := testutil.UnitTest(t)

	mockNotifier := notification.NewMockNotifier()
	scanNotifier, _ := notification2.NewScanNotifier(c, mockNotifier)

	const folderPath = "/test/oss/folderPath"

	// Act - run the test
	scanNotifier.SendSuccess(product.ProductOpenSource, folderPath)

	// Assert - check that there are messages sent
	assert.NotEmpty(t, mockNotifier.SentMessages())

	// Assert
	for _, msg := range mockNotifier.SentMessages() {
		scanParam := msg.(types.SnykScanParams)
		assert.Equal(t, types.Success, scanParam.Status)
		assert.Equal(t, folderPath, scanParam.FolderPath)
		assert.Equal(t, product.ProductOpenSource.ToProductCodename(), scanParam.Product)
	}
}

func Test_SendSuccess_SendsForSnykCode(t *testing.T) {
	c := testutil.UnitTest(t)

	mockNotifier := notification.NewMockNotifier()
	scanNotifier, _ := notification2.NewScanNotifier(c, mockNotifier)

	const folderPath = "/test/iac/folderPath"

	// Act - run the test
	scanNotifier.SendSuccess(product.ProductCode, folderPath)

	// Assert - check the messages matches the expected message for each product
	for _, msg := range mockNotifier.SentMessages() {
		scanParam := msg.(types.SnykScanParams)
		assert.Equal(t, types.Success, scanParam.Status)
		assert.Equal(t, folderPath, scanParam.FolderPath)
		assert.Equal(t, product.ProductCode.ToProductCodename(), scanParam.Product)
	}
}

func Test_SendSuccess_SendsForSnykCode_WithIgnores(t *testing.T) {
	c := testutil.UnitTest(t)

	mockNotifier := notification.NewMockNotifier()
	scanNotifier, _ := notification2.NewScanNotifier(c, mockNotifier)

	const folderPath = "/test/iac/folderPath"

	// Act - run the test
	scanNotifier.SendSuccess(product.ProductCode, folderPath)

	// Assert - check the messages matches the expected message for each product
	for _, msg := range mockNotifier.SentMessages() {
		scanParam := msg.(types.SnykScanParams)
		assert.Equal(t, types.Success, scanParam.Status)
		assert.Equal(t, folderPath, scanParam.FolderPath)
		assert.Equal(t, product.ProductCode.ToProductCodename(), scanParam.Product)
	}
}

func Test_SendSuccess_SendsForAllSnykIac(t *testing.T) {
	c := testutil.UnitTest(t)

	mockNotifier := notification.NewMockNotifier()
	scanNotifier, _ := notification2.NewScanNotifier(c, mockNotifier)

	const folderPath = "/test/iac/folderPath"

	// Act - run the test
	scanNotifier.SendSuccess(product.ProductInfrastructureAsCode, folderPath)

	// Assert - check the messages matches the expected message for each product
	for _, msg := range mockNotifier.SentMessages() {
		scanParam := msg.(types.SnykScanParams)
		assert.Equal(t, types.Success, scanParam.Status)
		assert.Equal(t, folderPath, scanParam.FolderPath)
		assert.Equal(t, product.ProductInfrastructureAsCode.ToProductCodename(), scanParam.Product)
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
	scanMessage, ok := msg.(types.SnykScanParams)
	if ok &&
		scanMessage.Status == testCase.expectedStatus &&
		scanMessage.Product == expectedProduct &&
		scanMessage.FolderPath == folderPath {
		return true
	}
	return false
}
