package snyk_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/ide/initialize"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	"github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
)

func TestScan_UsesEnabledProductLinesOnly(t *testing.T) {
	enabledScanner := snyk.NewTestProductScanner(snyk.ProductCode, true)
	disabledScanner := snyk.NewTestProductScanner(snyk.ProductOpenSource, false)

	scanner := snyk.NewDelegatingScanner(
		initialize.NewDelegatingInitializer(),
		performance.NewTestInstrumentor(),
		ux.NewTestAnalytics(),
		enabledScanner,
		disabledScanner,
	)

	scanner.Scan(context.Background(), "", snyk.NoopResultProcessor, "")

	assert.Eventually(
		t,
		func() bool {
			return 1 == enabledScanner.Scans && 0 == disabledScanner.Scans
		},
		1*time.Second,
		10*time.Millisecond,
	)
}

func TestScan_whenProductScannerEnabled_SendsAnalysisTriggered(t *testing.T) {
	enabledScanner := snyk.NewTestProductScanner(snyk.ProductCode, true)
	disabledScanner := snyk.NewTestProductScanner(snyk.ProductOpenSource, false)

	analytics := ux.NewTestAnalytics()
	scanner := snyk.NewDelegatingScanner(
		initialize.NewDelegatingInitializer(),
		performance.NewTestInstrumentor(),
		analytics,
		enabledScanner,
		disabledScanner,
	)

	scanner.Scan(context.Background(), "", snyk.NoopResultProcessor, "")

	assert.Equal(t, ux.AnalysisIsTriggeredProperties{
		AnalysisType:    []ux.AnalysisType{ux.CodeSecurity},
		TriggeredByUser: false,
	}, analytics.GetAnalytics()[0])
}

func TestScan_whenNoProductScannerEnabled_SendsNoAnalytics(t *testing.T) {
	disabledScanner := snyk.NewTestProductScanner(snyk.ProductOpenSource, false)

	analytics := ux.NewTestAnalytics()
	scanner := snyk.NewDelegatingScanner(
		initialize.NewDelegatingInitializer(),
		performance.NewTestInstrumentor(),
		analytics,
		disabledScanner,
	)

	scanner.Scan(context.Background(), "", snyk.NoopResultProcessor, "")

	assert.Len(t, analytics.GetAnalytics(), 0)
}
