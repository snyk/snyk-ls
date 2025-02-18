package scanstates

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestScanStateAggregator_Init(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetSnykOpenBrowserActionsEnabled(true)

	const folderPath = "/path/to/folder"

	emitter := &NoopEmitter{}

	agg := NewScanStateAggregator(c, emitter)
	agg.Init([]types.FilePath{folderPath})

	// 3) Validate initial states
	assert.False(t, agg.allScansStarted(true))
	assert.False(t, agg.allScansStarted(false))
	assert.False(t, agg.anyScanInProgress(true))
	assert.False(t, agg.anyScanInProgress(false))
	assert.False(t, agg.allScansSucceeded(true))
	assert.False(t, agg.allScansSucceeded(false))
	assert.False(t, agg.anyScanError(true))
	assert.False(t, agg.anyScanError(false))
}

func TestScanStateAggregator_SetState_InProgress(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetSnykOpenBrowserActionsEnabled(true)

	emitter := &NoopEmitter{}
	const folderPath = "/path/to/folder"

	agg := NewScanStateAggregator(c, emitter)
	agg.Init([]types.FilePath{folderPath, "/path/to/folder2"})

	newState := scanState{
		Status: InProgress,
		Err:    nil,
	}

	agg.SetScanState(folderPath, product.ProductOpenSource, false, newState)

	// Emitter should have been called once
	assert.Equal(t, 2, emitter.Calls)

	assert.False(t, agg.allScansStarted(false))
	assert.True(t, agg.anyScanInProgress(false))
}

func TestScanStateAggregator_SetState_Done(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetSnykOpenBrowserActionsEnabled(true)

	emitter := &NoopEmitter{}
	const folderPath = "/path/to/folder"

	agg := NewScanStateAggregator(c, emitter)
	agg.Init([]types.FilePath{folderPath})

	doneState := scanState{
		Status: Success,
		Err:    nil,
	}
	agg.SetScanState(folderPath, product.ProductOpenSource, false, doneState)

	assert.Equal(t, 2, emitter.Calls)

	assert.False(t, agg.allScansSucceeded(false))
	assert.False(t, agg.anyScanError(false))
}

func TestScanStateAggregator_SetState_Error(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetSnykCodeEnabled(true)

	emitter := &NoopEmitter{}
	const folderPath = "/path/to/folder"

	agg := NewScanStateAggregator(c, emitter)
	agg.Init([]types.FilePath{folderPath})

	errState := scanState{
		Status: Error,
		Err:    errors.New("something went wrong"),
	}
	agg.SetScanState(folderPath, product.ProductCode, false, errState)

	assert.Equal(t, 2, emitter.Calls, "Emit called again")

	assert.True(t, agg.anyScanError(false), "At least one working scan is in ERROR")
	assert.False(t, agg.allScansSucceeded(false))
}

func TestScanStateAggregator_SetState_AllSuccess(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetSnykOpenBrowserActionsEnabled(true)
	c.SetSnykCodeEnabled(true)
	c.SetSnykIacEnabled(true)

	emitter := &NoopEmitter{}
	const folderPath = "/path/to/folder"

	agg := NewScanStateAggregator(c, emitter)
	agg.Init([]types.FilePath{folderPath})

	doneState := scanState{
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
	assert.Equal(t, 7, emitter.Calls)

	assert.True(t, agg.allScansSucceeded(true))
	assert.True(t, agg.allScansSucceeded(false))
	assert.False(t, agg.anyScanError(true))
	assert.False(t, agg.anyScanError(false))
}

func TestScanStateAggregator_SetState_NonExistingFolder(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetSnykOpenBrowserActionsEnabled(true)

	emitter := &NoopEmitter{}
	const folderPath = "/path/to/folder"

	agg := NewScanStateAggregator(c, emitter)
	agg.Init([]types.FilePath{folderPath})

	doneState := scanState{
		Status: Success,
		Err:    nil,
	}
	agg.SetScanState("/non/existing/folder", product.ProductOpenSource, true, doneState)
	assert.Equal(t, 1, emitter.Calls)

	assert.False(t, agg.allScansStarted(true))
	assert.False(t, agg.allScansStarted(false))
}

func TestScanStateAggregator_SetScanInProgress(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetSnykOpenBrowserActionsEnabled(true)

	emitter := &NoopEmitter{}
	agg := NewScanStateAggregator(c, emitter)

	folder := types.FilePath("/path/folder")
	agg.Init([]types.FilePath{folder})

	agg.SetScanInProgress(folder, product.ProductOpenSource, false)
	assert.Equal(t, 2, emitter.Calls)

	assert.True(t, agg.anyScanInProgress(false))
	assert.False(t, agg.anyScanError(false))
}

func TestScanStateAggregator_SetScanDone(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetSnykOpenBrowserActionsEnabled(true)
	c.SetSnykCodeEnabled(true)

	emitter := &NoopEmitter{}
	agg := NewScanStateAggregator(c, emitter)

	folder := types.FilePath("/path/folder")
	agg.Init([]types.FilePath{folder})

	agg.SetScanInProgress(folder, product.ProductOpenSource, false)
	assert.Equal(t, 2, emitter.Calls)

	agg.SetScanDone(folder, product.ProductOpenSource, false, nil)
	assert.Equal(t, 3, emitter.Calls)

	assert.False(t, agg.anyScanError(false))
	assert.True(t, agg.anyScanSucceeded(false))

	testErr := errors.New("some error")
	agg.SetScanDone(folder, product.ProductCode, false, testErr)
	assert.Equal(t, 4, emitter.Calls)

	assert.True(t, agg.anyScanError(false))
}

func TestScanStateAggregator_StateSnapshot(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetSnykOpenBrowserActionsEnabled(true)
	c.SetSnykCodeEnabled(true)

	emitter := &NoopEmitter{}
	agg := NewScanStateAggregator(c, emitter)

	folder := types.FilePath("/path/folder")
	agg.Init([]types.FilePath{folder})

	// Make sure everything is NOT_STARTED initially
	snapshot := agg.StateSnapshot()
	assert.False(t, snapshot.AllScansStartedReference)
	assert.False(t, snapshot.AllScansStartedWorkingDirectory)
	assert.False(t, snapshot.AnyScanInProgressReference)
	assert.False(t, snapshot.AnyScanInProgressWorkingDirectory)
	assert.False(t, snapshot.AnyScanSucceededReference)
	assert.False(t, snapshot.AnyScanSucceededWorkingDirectory)
	assert.False(t, snapshot.AllScansSucceededReference)
	assert.False(t, snapshot.AllScansSucceededWorkingDirectory)
	assert.False(t, snapshot.AnyScanErrorReference)
	assert.False(t, snapshot.AnyScanErrorWorkingDirectory)

	// Now set one product to InProgress on working dir
	agg.SetScanInProgress(folder, product.ProductOpenSource, false)
	snapshot = agg.StateSnapshot()
	assert.True(t, snapshot.AnyScanInProgressWorkingDirectory)
	assert.False(t, snapshot.AnyScanInProgressReference)

	// Mark that same product as Success
	agg.SetScanDone(folder, product.ProductOpenSource, false, nil)
	snapshot = agg.StateSnapshot()
	assert.True(t, snapshot.AnyScanSucceededWorkingDirectory)
	assert.False(t, snapshot.AnyScanSucceededReference)
	assert.False(t, snapshot.AnyScanErrorWorkingDirectory)
	assert.False(t, snapshot.AllScansSucceededWorkingDirectory)

	// Introduce an error for reference scans
	agg.SetScanDone(folder, product.ProductCode, true, errors.New("error"))
	snapshot = agg.StateSnapshot()
	assert.True(t, snapshot.AnyScanErrorReference)
}

func TestScanStateAggregator_OnlyEnabledProductsShouldBeCounted(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetSnykOpenBrowserActionsEnabled(true)
	c.SetSnykCodeEnabled(true)
	c.SetSnykIacEnabled(false)

	emitter := &NoopEmitter{}
	const folderPath = "/path/to/folder"

	agg := NewScanStateAggregator(c, emitter)
	agg.Init([]types.FilePath{folderPath})

	newState := scanState{
		Status: InProgress,
		Err:    nil,
	}

	agg.SetScanState(folderPath, product.ProductOpenSource, false, newState)
	agg.SetScanState(folderPath, product.ProductCode, false, newState)

	agg.SetScanState(folderPath, product.ProductOpenSource, true, newState)
	agg.SetScanState(folderPath, product.ProductCode, true, newState)

	assert.Equal(t, 5, emitter.Calls)

	assert.True(t, agg.allScansStarted(false))
	assert.True(t, agg.anyScanInProgress(false))
	snapshot := agg.StateSnapshot()
	assert.Equal(t, snapshot.ScansInProgressCount, 4, "IaC won't be counted since it's disabled")
}
