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
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	"github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestScan_UsesEnabledProductLinesOnly(t *testing.T) {
	testutil.UnitTest(t)
	enabledScanner := NewTestProductScanner(product.ProductCode, true)
	disabledScanner := NewTestProductScanner(product.ProductOpenSource, false)
	scanner, _, _ := setupScanner(enabledScanner, disabledScanner)

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
	analytics *ux.TestAnalytics,
	scanNotifier ScanNotifier,
) {
	analytics = ux.NewTestAnalytics()
	scanNotifier = NewMockScanNotifier()
	notifier := notification.NewNotifier()
	apiClient := &snyk_api.FakeApiClient{CodeEnabled: false}
	er := error_reporting.NewTestErrorReporter()
	authenticationProvider := NewFakeCliAuthenticationProvider()
	authenticationService := NewAuthenticationService(authenticationProvider, analytics, er, notifier)
	scanner = NewDelegatingScanner(
		initialize.NewDelegatingInitializer(),
		performance.NewTestInstrumentor(),
		analytics,
		scanNotifier,
		apiClient,
		authenticationService,
		testProductScanners...,
	)
	return scanner, analytics, scanNotifier
}

func TestScan_whenProductScannerEnabled_SendsAnalysisTriggered(t *testing.T) {
	testutil.UnitTest(t)
	config.CurrentConfig().SetSnykCodeEnabled(true)
	enabledScanner := NewTestProductScanner(product.ProductCode, true)
	disabledScanner := NewTestProductScanner(product.ProductOpenSource, false)
	scanner, analytics, _ := setupScanner(enabledScanner, disabledScanner)

	scanner.Scan(context.Background(), "", NoopResultProcessor, "")

	assert.Contains(t, analytics.GetAnalytics(),
		ux.AnalysisIsTriggeredProperties{
			AnalysisType:    []ux.AnalysisType{ux.CodeQuality, ux.CodeSecurity},
			TriggeredByUser: false,
		})
}

func TestScan_whenNoProductScannerEnabled_SendsNoAnalytics(t *testing.T) {
	disabledScanner := NewTestProductScanner(product.ProductOpenSource, false)
	scanner, analytics, _ := setupScanner(disabledScanner)

	scanner.Scan(context.Background(), "", NoopResultProcessor, "")

	assert.Len(t, analytics.GetAnalytics(), 0)
}

func Test_userNotAuthenticated_ScanSkipped(t *testing.T) {
	// Arrange
	productScanner := NewTestProductScanner(product.ProductOpenSource, true)
	scanner, _, _ := setupScanner(productScanner)
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
	scanner, _, _ := setupScanner(productScanner)
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
	scanner, _, scanNotifier := setupScanner(enabledScanner)
	mockScanNotifier := scanNotifier.(*MockScanNotifier)

	scanner.Scan(context.Background(), "", NoopResultProcessor, "")

	assert.NotEmpty(t, mockScanNotifier.InProgressCalls())
}
