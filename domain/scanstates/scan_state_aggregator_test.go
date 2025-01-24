package scanstates

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestScanStateAggregator_Init(t *testing.T) {
	c := testutil.UnitTest(t)
	const folderPath = "/path/to/folder"

	emitter := &NoopEmitter{}

	agg := NewScanStateAggregator(c, emitter)
	agg.Init([]string{folderPath})

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

	emitter := &NoopEmitter{}
	const folderPath = "/path/to/folder"

	agg := NewScanStateAggregator(c, emitter)
	agg.Init([]string{folderPath, "/path/to/folder2"})

	newState := ScanState{
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

	emitter := &NoopEmitter{}
	const folderPath = "/path/to/folder"

	agg := NewScanStateAggregator(c, emitter)
	agg.Init([]string{folderPath})

	doneState := ScanState{
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

	emitter := &NoopEmitter{}
	const folderPath = "/path/to/folder"

	agg := NewScanStateAggregator(c, emitter)
	agg.Init([]string{folderPath})

	errState := ScanState{
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

	emitter := &NoopEmitter{}
	const folderPath = "/path/to/folder"

	agg := NewScanStateAggregator(c, emitter)
	agg.Init([]string{folderPath})

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
	assert.Equal(t, 7, emitter.Calls)

	assert.True(t, agg.allScansSucceeded(true))
	assert.True(t, agg.allScansSucceeded(false))
	assert.False(t, agg.anyScanError(true))
	assert.False(t, agg.anyScanError(false))
}

func TestScanStateAggregator_SetState_NonExistingFolder(t *testing.T) {
	c := testutil.UnitTest(t)

	emitter := &NoopEmitter{}
	const folderPath = "/path/to/folder"

	agg := NewScanStateAggregator(c, emitter)
	agg.Init([]string{folderPath})

	doneState := ScanState{
		Status: Success,
		Err:    nil,
	}
	agg.SetScanState("/non/existing/folder", product.ProductOpenSource, true, doneState)
	assert.Equal(t, 1, emitter.Calls)

	assert.False(t, agg.allScansStarted(true))
	assert.False(t, agg.allScansStarted(false))
}
