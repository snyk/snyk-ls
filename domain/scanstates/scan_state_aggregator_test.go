package scanstates

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestScanStateAggregator_Init(t *testing.T) {
	c := testutil.UnitTest(t)

	emitter := &NoopEmitter{}
	const folderPath = "/path/to/folder"
	sc := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	notifier := notification.NewNotifier()
	w := workspace.New(c, performance.NewInstrumentor(), sc, nil, nil, notifier, nil, nil)
	c.SetTrustedFolderFeatureEnabled(true)
	c.SetTrustedFolders([]string{folderPath})
	w.AddFolder(workspace.NewFolder(c, folderPath, folderPath, sc, nil, scanNotifier, notifier, nil, nil))

	agg := NewScanStateAggregator(c, emitter)

	// 3) Validate initial states
	assert.True(t, agg.AllScansStarted(true))
	assert.True(t, agg.AllScansStarted(false))
	assert.False(t, agg.AnyScanInProgress(true))
	assert.False(t, agg.AnyScanInProgress(false))
	assert.False(t, agg.AllScansSucceeded(true))
	assert.False(t, agg.AllScansSucceeded(false))
	assert.False(t, agg.AnyScanError(true))
	assert.False(t, agg.AnyScanError(false))
}

func TestScanStateAggregator_SetState_InProgress(t *testing.T) {
	c := testutil.UnitTest(t)

	emitter := &NoopEmitter{}
	const folderPath = "/path/to/folder"
	sc := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	notifier := notification.NewNotifier()
	w := workspace.New(c, performance.NewInstrumentor(), sc, nil, nil, notifier, nil, nil)
	c.SetTrustedFolderFeatureEnabled(true)
	c.SetTrustedFolders([]string{folderPath})
	w.AddFolder(workspace.NewFolder(c, folderPath, folderPath, sc, nil, scanNotifier, notifier, nil, nil))

	agg := NewScanStateAggregator(c, emitter)

	newState := ScanState{
		Status: InProgress,
		Err:    nil,
	}
	agg.SetScanState(folderPath, product.ProductOpenSource, false, newState)

	// Emitter should have been called once
	assert.Equal(t, 1, emitter.Calls)

	assert.False(t, agg.AllScansStarted(false))
	assert.True(t, agg.AnyScanInProgress(false))
}

func TestScanStateAggregator_SetState_Done(t *testing.T) {
	c := testutil.UnitTest(t)

	emitter := &NoopEmitter{}
	const folderPath = "/path/to/folder"
	sc := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	notifier := notification.NewNotifier()
	w := workspace.New(c, performance.NewInstrumentor(), sc, nil, nil, notifier, nil, nil)
	c.SetTrustedFolderFeatureEnabled(true)
	c.SetTrustedFolders([]string{folderPath})
	w.AddFolder(workspace.NewFolder(c, folderPath, folderPath, sc, nil, scanNotifier, notifier, nil, nil))

	agg := NewScanStateAggregator(c, emitter)

	doneState := ScanState{
		Status: Success,
		Err:    nil,
	}
	agg.SetScanState(folderPath, product.ProductOpenSource, false, doneState)

	assert.Equal(t, 1, emitter.Calls)

	assert.False(t, agg.AllScansSucceeded(false))
	assert.False(t, agg.AnyScanError(false))
}

func TestScanStateAggregator_SetState_Error(t *testing.T) {
	c := testutil.UnitTest(t)

	emitter := &NoopEmitter{}
	const folderPath = "/path/to/folder"
	sc := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	notifier := notification.NewNotifier()
	w := workspace.New(c, performance.NewInstrumentor(), sc, nil, nil, notifier, nil, nil)
	c.SetTrustedFolderFeatureEnabled(true)
	c.SetTrustedFolders([]string{folderPath})
	w.AddFolder(workspace.NewFolder(c, folderPath, folderPath, sc, nil, scanNotifier, notifier, nil, nil))

	agg := NewScanStateAggregator(c, emitter)

	errState := ScanState{
		Status: Error,
		Err:    errors.New("something went wrong"),
	}
	agg.SetScanState(folderPath, product.ProductCode, false, errState)

	assert.Equal(t, 1, emitter.Calls, "Emit called again")

	assert.True(t, agg.AnyScanError(false), "At least one working scan is in ERROR")
	assert.False(t, agg.AllScansSucceeded(false))
}

func TestScanStateAggregator_SetState_AllSuccess(t *testing.T) {
	c := testutil.UnitTest(t)

	emitter := &NoopEmitter{}
	const folderPath = "/path/to/folder"
	sc := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	notifier := notification.NewNotifier()
	w := workspace.New(c, performance.NewInstrumentor(), sc, nil, nil, notifier, nil, nil)
	c.SetTrustedFolderFeatureEnabled(true)
	c.SetTrustedFolders([]string{folderPath})
	w.AddFolder(workspace.NewFolder(c, folderPath, folderPath, sc, nil, scanNotifier, notifier, nil, nil))

	agg := NewScanStateAggregator(c, emitter)

	doneState := ScanState{
		Status: Success,
		Err:    nil,
	}
	agg.SetScanState(folderPath, product.ProductOpenSource, true, doneState)
	agg.SetScanState(folderPath, product.ProductCode, true, doneState)
	agg.SetScanState(folderPath, product.ProductInfrastructureAsCode, true, doneState)

	agg.SetScanState(folderPath, product.ProductOpenSource, false, doneState)
	agg.SetScanState(folderPath, product.ProductCode, false, doneState)
	agg.SetScanState(folderPath, product.ProductInfrastructureAsCode, false, doneState)

	// Emitter called 3 times total
	assert.Equal(t, 6, emitter.Calls)

	assert.True(t, agg.AllScansSucceeded(true))
	assert.True(t, agg.AllScansSucceeded(false))
	assert.False(t, agg.AnyScanError(true))
	assert.False(t, agg.AnyScanError(false))
}

func TestScanStateAggregator_SetState_NonExistingFolder(t *testing.T) {
	c := testutil.UnitTest(t)

	emitter := &NoopEmitter{}
	const folderPath = "/path/to/folder"
	sc := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	notifier := notification.NewNotifier()
	w := workspace.New(c, performance.NewInstrumentor(), sc, nil, nil, notifier, nil, nil)
	c.SetTrustedFolderFeatureEnabled(true)
	c.SetTrustedFolders([]string{folderPath})
	w.AddFolder(workspace.NewFolder(c, folderPath, folderPath, sc, nil, scanNotifier, notifier, nil, nil))

	agg := NewScanStateAggregator(c, emitter)

	doneState := ScanState{
		Status: Success,
		Err:    nil,
	}
	agg.SetScanState("/non/existing/folder", product.ProductOpenSource, true, doneState)
	assert.Equal(t, 0, emitter.Calls)

	assert.True(t, agg.AllScansStarted(true))
	assert.True(t, agg.AllScansStarted(false))
}
