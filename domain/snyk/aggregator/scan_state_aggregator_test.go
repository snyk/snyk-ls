package aggregator

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
	w := workspace.New(c, performance.NewInstrumentor(), sc, nil, nil, notifier, nil)
	c.SetTrustedFolderFeatureEnabled(true)
	c.SetTrustedFolders([]string{folderPath})
	w.AddFolder(workspace.NewFolder(c, folderPath, folderPath, sc, nil, scanNotifier, notifier, nil))

	agg := NewScanStateAggregator(emitter, c)

	// 3) Validate initial states
	assert.True(t, agg.AreAllScansNotStarted(true))
	assert.True(t, agg.AreAllScansNotStarted(false))
	assert.False(t, agg.HasAnyScanInProgress(true))
	assert.False(t, agg.HasAnyScanInProgress(false))
	assert.False(t, agg.HaveAllScansSucceeded(true))
	assert.False(t, agg.HaveAllScansSucceeded(false))
	assert.False(t, agg.HasAnyScanError(true))
	assert.False(t, agg.HasAnyScanError(false))
}

func TestScanStateAggregator_SetState_InProgress(t *testing.T) {
	c := testutil.UnitTest(t)

	emitter := &NoopEmitter{}
	const folderPath = "/path/to/folder"
	sc := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	notifier := notification.NewNotifier()
	w := workspace.New(c, performance.NewInstrumentor(), sc, nil, nil, notifier, nil)
	c.SetTrustedFolderFeatureEnabled(true)
	c.SetTrustedFolders([]string{folderPath})
	w.AddFolder(workspace.NewFolder(c, folderPath, folderPath, sc, nil, scanNotifier, notifier, nil))

	agg := NewScanStateAggregator(emitter, c)

	newState := ScanState{
		Status: InProgress,
		Err:    nil,
	}
	agg.SetScanState(folderPath, product.ProductOpenSource, false, newState)

	// Emitter should have been called once
	assert.Equal(t, 1, emitter.calls)

	assert.False(t, agg.AreAllScansNotStarted(false))
	assert.True(t, agg.HasAnyScanInProgress(false))
}

func TestScanStateAggregator_SetState_Done(t *testing.T) {
	c := testutil.UnitTest(t)

	emitter := &NoopEmitter{}
	const folderPath = "/path/to/folder"
	sc := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	notifier := notification.NewNotifier()
	w := workspace.New(c, performance.NewInstrumentor(), sc, nil, nil, notifier, nil)
	c.SetTrustedFolderFeatureEnabled(true)
	c.SetTrustedFolders([]string{folderPath})
	w.AddFolder(workspace.NewFolder(c, folderPath, folderPath, sc, nil, scanNotifier, notifier, nil))

	agg := NewScanStateAggregator(emitter, c)

	doneState := ScanState{
		Status: Success,
		Err:    nil,
	}
	agg.SetScanState(folderPath, product.ProductOpenSource, false, doneState)

	assert.Equal(t, 1, emitter.calls)

	assert.False(t, agg.HaveAllScansSucceeded(false))
	assert.False(t, agg.HasAnyScanError(false))
}

func TestScanStateAggregator_SetState_Error(t *testing.T) {
	c := testutil.UnitTest(t)

	emitter := &NoopEmitter{}
	const folderPath = "/path/to/folder"
	sc := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	notifier := notification.NewNotifier()
	w := workspace.New(c, performance.NewInstrumentor(), sc, nil, nil, notifier, nil)
	c.SetTrustedFolderFeatureEnabled(true)
	c.SetTrustedFolders([]string{folderPath})
	w.AddFolder(workspace.NewFolder(c, folderPath, folderPath, sc, nil, scanNotifier, notifier, nil))

	agg := NewScanStateAggregator(emitter, c)

	errState := ScanState{
		Status: Error,
		Err:    errors.New("something went wrong"),
	}
	agg.SetScanState(folderPath, product.ProductCode, false, errState)

	assert.Equal(t, 1, emitter.calls, "Emit called again")

	assert.True(t, agg.HasAnyScanError(false), "At least one working scan is in ERROR")
	assert.False(t, agg.HaveAllScansSucceeded(false))
}

func TestScanStateAggregator_SetState_AllSuccess(t *testing.T) {
	c := testutil.UnitTest(t)

	emitter := &NoopEmitter{}
	const folderPath = "/path/to/folder"
	sc := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	notifier := notification.NewNotifier()
	w := workspace.New(c, performance.NewInstrumentor(), sc, nil, nil, notifier, nil)
	c.SetTrustedFolderFeatureEnabled(true)
	c.SetTrustedFolders([]string{folderPath})
	w.AddFolder(workspace.NewFolder(c, folderPath, folderPath, sc, nil, scanNotifier, notifier, nil))

	agg := NewScanStateAggregator(emitter, c)

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
	assert.Equal(t, 6, emitter.calls)

	assert.True(t, agg.HaveAllScansSucceeded(true))
	assert.True(t, agg.HaveAllScansSucceeded(false))
	assert.False(t, agg.HasAnyScanError(true))
	assert.False(t, agg.HasAnyScanError(false))
}

func TestScanStateAggregator_SetState_NonExistingFolder(t *testing.T) {
	c := testutil.UnitTest(t)

	emitter := &NoopEmitter{}
	const folderPath = "/path/to/folder"
	sc := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	notifier := notification.NewNotifier()
	w := workspace.New(c, performance.NewInstrumentor(), sc, nil, nil, notifier, nil)
	c.SetTrustedFolderFeatureEnabled(true)
	c.SetTrustedFolders([]string{folderPath})
	w.AddFolder(workspace.NewFolder(c, folderPath, folderPath, sc, nil, scanNotifier, notifier, nil))

	agg := NewScanStateAggregator(emitter, c)

	doneState := ScanState{
		Status: Success,
		Err:    nil,
	}
	agg.SetScanState("/non/existing/folder", product.ProductOpenSource, true, doneState)
	assert.Equal(t, 0, emitter.calls)

	assert.True(t, agg.AreAllScansNotStarted(true))
	assert.True(t, agg.AreAllScansNotStarted(false))
}
