/*
 * © 2022 Snyk Limited All rights reserved.
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

package snyk

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/initialize"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestScan_UsesEnabledProductLinesOnly(t *testing.T) {
	testutil.UnitTest(t)
	enabledScanner := NewTestProductScanner(product.ProductCode, true)
	disabledScanner := NewTestProductScanner(product.ProductOpenSource, false)
	scanner, _ := setupScanner(enabledScanner, disabledScanner)

	scanner.Scan(context.Background(), "", NoopResultProcessor, "")

	assert.Eventually(
		t,
		func() bool {
			return 1 == enabledScanner.Scans() && 0 == disabledScanner.Scans()
		},
		1*time.Second,
		10*time.Millisecond,
	)
}

func setupScanner(testProductScanners ...ProductScanner) (
	scanner Scanner,
	scanNotifier ScanNotifier,
) {
	c := config.CurrentConfig()
	scanNotifier = NewMockScanNotifier()
	notifier := notification.NewNotifier()
	apiClient := &snyk_api.FakeApiClient{CodeEnabled: false}
	er := error_reporting.NewTestErrorReporter()
	authenticationProvider := authentication.NewFakeCliAuthenticationProvider(c)
	authenticationProvider.IsAuthenticated = true
	authenticationService := authentication.NewAuthenticationService(c, []authentication.AuthenticationProvider{authenticationProvider}, er, notifier)
	scanner = NewDelegatingScanner(c, initialize.NewDelegatingInitializer(), performance.NewInstrumentor(), scanNotifier, apiClient, authenticationService, notifier, testProductScanners...)
	return scanner, scanNotifier
}

func Test_userNotAuthenticated_ScanSkipped(t *testing.T) {
	// Arrange
	productScanner := NewTestProductScanner(product.ProductOpenSource, true)
	scanner, _ := setupScanner(productScanner)
	config.CurrentConfig().SetToken("")
	emptyToken := !config.CurrentConfig().NonEmptyToken()

	// Act
	scanner.Scan(context.Background(), "", NoopResultProcessor, "")

	// Assert
	assert.True(t, emptyToken)
	assert.Equal(t, 0, productScanner.scans)
}

func Test_ScanStarted_TokenChanged_ScanCancelled(t *testing.T) {
	// Arrange
	config.CurrentConfig().SetToken("")
	productScanner := NewTestProductScanner(product.ProductOpenSource, true)
	productScanner.SetScanDuration(2 * time.Second)
	scanner, _ := setupScanner(productScanner)
	done := make(chan bool)

	// Act
	go func() {
		scanner.Scan(context.Background(), "", NoopResultProcessor, "")
		done <- true
	}()
	time.Sleep(500 * time.Millisecond) // Wait for the product scanner to start running
	config.CurrentConfig().SetToken(uuid.New().String())

	// Assert
	// Need to wait for the scan to be done before checking whether the product scanner was used
	<-done

	assert.Zero(t, productScanner.scans)
}

func TestScan_whenProductScannerEnabled_SendsInProgress(t *testing.T) {
	testutil.UnitTest(t)
	config.CurrentConfig().SetSnykCodeEnabled(true)
	enabledScanner := NewTestProductScanner(product.ProductCode, true)
	scanner, scanNotifier := setupScanner(enabledScanner)
	mockScanNotifier := scanNotifier.(*MockScanNotifier)

	scanner.Scan(context.Background(), "", NoopResultProcessor, "")

	assert.NotEmpty(t, mockScanNotifier.InProgressCalls())
}
