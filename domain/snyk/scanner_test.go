package snyk

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/initialize"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	"github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestScan_UsesEnabledProductLinesOnly(t *testing.T) {
	testutil.UnitTest(t)
	enabledScanner := NewTestProductScanner(ProductCode, true)
	disabledScanner := NewTestProductScanner(ProductOpenSource, false)

	scanner := NewDelegatingScanner(
		initialize.NewDelegatingInitializer(),
		performance.NewTestInstrumentor(),
		ux.NewTestAnalytics(),
		enabledScanner,
		disabledScanner,
	)

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

func TestScan_whenProductScannerEnabled_SendsAnalysisTriggered(t *testing.T) {
	testutil.UnitTest(t)
	enabledScanner := NewTestProductScanner(ProductCode, true)
	disabledScanner := NewTestProductScanner(ProductOpenSource, false)

	analytics := ux.NewTestAnalytics()
	scanner := NewDelegatingScanner(
		initialize.NewDelegatingInitializer(),
		performance.NewTestInstrumentor(),
		analytics,
		enabledScanner,
		disabledScanner,
	)

	scanner.Scan(context.Background(), "", NoopResultProcessor, "")

	assert.Equal(t, ux.AnalysisIsTriggeredProperties{
		AnalysisType:    []ux.AnalysisType{ux.CodeSecurity},
		TriggeredByUser: false,
	}, analytics.GetAnalytics()[0])
}

func TestScan_whenNoProductScannerEnabled_SendsNoAnalytics(t *testing.T) {
	disabledScanner := NewTestProductScanner(ProductOpenSource, false)

	analytics := ux.NewTestAnalytics()
	scanner := NewDelegatingScanner(
		initialize.NewDelegatingInitializer(),
		performance.NewTestInstrumentor(),
		analytics,
		disabledScanner,
	)

	scanner.Scan(context.Background(), "", NoopResultProcessor, "")

	assert.Len(t, analytics.GetAnalytics(), 0)
}

func Test_userNotAuthenticated_ScanSkipped(t *testing.T) {
	// Arrange
	productScanner := NewTestProductScanner(ProductOpenSource, true)
	scanner := NewDelegatingScanner(
		initialize.NewDelegatingInitializer(),
		performance.NewTestInstrumentor(),
		ux.NewTestAnalytics(),
		productScanner,
	)
	config.CurrentConfig().SetToken("")
	isAuthenticated := config.CurrentConfig().Authenticated()

	// Act
	scanner.Scan(context.Background(), "", NoopResultProcessor, "")

	// Assert
	assert.False(t, isAuthenticated)
	assert.Equal(t, 0, productScanner.scans)
}

type TestInitializer struct {
	initCalled   chan bool
	initFinished chan bool
}

func (t *TestInitializer) Init() {
	t.initCalled <- true
	t.initFinished <- true
}

func Test_ScanInitialization_TokenChanged_ScanCancelled(t *testing.T) {
	// Arrange
	// Using an initializer that blocks execution until it's channels are read
	fakeInitializer := &TestInitializer{}
	productScanner := NewTestProductScanner(ProductOpenSource, true)
	scanner := NewDelegatingScanner(
		initialize.NewDelegatingInitializer(fakeInitializer),
		performance.NewTestInstrumentor(),
		ux.NewTestAnalytics(),
		productScanner,
	)
	done := make(chan bool)

	// Act
	go func() {
		scanner.Scan(context.Background(), "", NoopResultProcessor, "")
		done <- true
	}()
	<-fakeInitializer.initCalled // Wait for Init() to be called on the initializer before changing the token
	config.CurrentConfig().SetToken(uuid.New().String())

	// Assert
	// Reading from this channel will finish the Init() call
	<-fakeInitializer.initFinished
	// Need to wait for the scan to be done before checking whether the product scanner was used
	<-done
	
	assert.Zero(t, productScanner.scans)
}
