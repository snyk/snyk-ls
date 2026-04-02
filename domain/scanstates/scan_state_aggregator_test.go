package scanstates

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func defaultResolver(engine workflow.Engine) types.ConfigResolverInterface {
	return testutil.DefaultConfigResolver(engine)
}

func TestScanStateAggregator_Init(t *testing.T) {
	engine := testutil.UnitTest(t)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingEnableSnykOpenBrowserActions), true)

	const folderPath = "/path/to/folder"

	ctrl := gomock.NewController(t)
	emitter := NewMockScanStateChangeEmitter(ctrl)
	emitter.EXPECT().Emit(gomock.Any()).AnyTimes()

	agg := NewScanStateAggregator(engine.GetConfiguration(), engine.GetLogger(), emitter, defaultResolver(engine), engine)
	agg.Init([]types.FilePath{folderPath})

	// 3) Validate initial states
	snapshot := agg.StateSnapshot()
	assert.False(t, snapshot.AllScansStartedReference)
	assert.False(t, snapshot.AllScansStartedWorkingDirectory)
	assert.False(t, snapshot.AnyScanInProgressReference)
	assert.False(t, snapshot.AnyScanInProgressWorkingDirectory)
	assert.False(t, snapshot.AllScansSucceededReference)
	assert.False(t, snapshot.AllScansSucceededWorkingDirectory)
	assert.False(t, snapshot.AnyScanErrorReference)
	assert.False(t, snapshot.AnyScanErrorWorkingDirectory)
}

func TestScanStateAggregator_SetState_InProgress(t *testing.T) {
	engine := testutil.UnitTest(t)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingEnableSnykOpenBrowserActions), true)

	ctrl := gomock.NewController(t)
	emitter := NewMockScanStateChangeEmitter(ctrl)
	emitter.EXPECT().Emit(gomock.Any()).Times(2)
	const folderPath = "/path/to/folder"

	agg := NewScanStateAggregator(engine.GetConfiguration(), engine.GetLogger(), emitter, defaultResolver(engine), engine)
	agg.Init([]types.FilePath{folderPath, "/path/to/folder2"})

	newState := scanState{
		Status: InProgress,
		Err:    nil,
	}

	agg.SetScanState(folderPath, product.ProductOpenSource, false, newState)

	// Emitter should have been called once

	snapshot := agg.StateSnapshot()
	assert.False(t, snapshot.AllScansStartedWorkingDirectory)
	assert.True(t, snapshot.AnyScanInProgressWorkingDirectory)
}

func TestScanStateAggregator_SetState_Done(t *testing.T) {
	engine := testutil.UnitTest(t)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingEnableSnykOpenBrowserActions), true)

	ctrl := gomock.NewController(t)
	emitter := NewMockScanStateChangeEmitter(ctrl)
	emitter.EXPECT().Emit(gomock.Any()).Times(2)
	const folderPath = "/path/to/folder"

	agg := NewScanStateAggregator(engine.GetConfiguration(), engine.GetLogger(), emitter, defaultResolver(engine), engine)
	agg.Init([]types.FilePath{folderPath})

	doneState := scanState{
		Status: Success,
		Err:    nil,
	}
	agg.SetScanState(folderPath, product.ProductOpenSource, false, doneState)

	snapshot := agg.StateSnapshot()
	assert.False(t, snapshot.AllScansSucceededWorkingDirectory)
	assert.False(t, snapshot.AnyScanErrorWorkingDirectory)
}

func TestScanStateAggregator_SetState_Error(t *testing.T) {
	engine := testutil.UnitTest(t)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)

	ctrl := gomock.NewController(t)
	emitter := NewMockScanStateChangeEmitter(ctrl)
	emitter.EXPECT().Emit(gomock.Any()).Times(2)
	const folderPath = "/path/to/folder"

	agg := NewScanStateAggregator(engine.GetConfiguration(), engine.GetLogger(), emitter, defaultResolver(engine), engine)
	agg.Init([]types.FilePath{folderPath})

	errState := scanState{
		Status: Error,
		Err:    errors.New("something went wrong"),
	}
	agg.SetScanState(folderPath, product.ProductCode, false, errState)

	snapshot := agg.StateSnapshot()
	assert.True(t, snapshot.AnyScanErrorWorkingDirectory, "At least one working scan is in ERROR")
	assert.False(t, snapshot.AllScansSucceededWorkingDirectory)
}

func TestScanStateAggregator_SetState_AllSuccess(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingEnableSnykOpenBrowserActions), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), true)

	ctrl := gomock.NewController(t)
	emitter := NewMockScanStateChangeEmitter(ctrl)
	emitter.EXPECT().Emit(gomock.Any()).Times(7)
	const folderPath = "/path/to/folder"

	agg := NewScanStateAggregator(engine.GetConfiguration(), engine.GetLogger(), emitter, defaultResolver(engine), engine)
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

	snapshot := agg.StateSnapshot()
	assert.True(t, snapshot.AllScansSucceededReference)
	assert.True(t, snapshot.AllScansSucceededWorkingDirectory)
	assert.False(t, snapshot.AnyScanErrorReference)
	assert.False(t, snapshot.AnyScanErrorWorkingDirectory)
}

func TestScanStateAggregator_SetState_NonExistingFolder(t *testing.T) {
	engine := testutil.UnitTest(t)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingEnableSnykOpenBrowserActions), true)

	ctrl := gomock.NewController(t)
	emitter := NewMockScanStateChangeEmitter(ctrl)
	emitter.EXPECT().Emit(gomock.Any()).Times(1)
	const folderPath = "/path/to/folder"

	agg := NewScanStateAggregator(engine.GetConfiguration(), engine.GetLogger(), emitter, defaultResolver(engine), engine)
	agg.Init([]types.FilePath{folderPath})

	doneState := scanState{
		Status: Success,
		Err:    nil,
	}
	agg.SetScanState("/non/existing/folder", product.ProductOpenSource, true, doneState)

	snapshot := agg.StateSnapshot()
	assert.False(t, snapshot.AllScansStartedReference)
	assert.False(t, snapshot.AllScansStartedWorkingDirectory)
}

func TestScanStateAggregator_SetScanInProgress(t *testing.T) {
	engine := testutil.UnitTest(t)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingEnableSnykOpenBrowserActions), true)

	ctrl := gomock.NewController(t)
	emitter := NewMockScanStateChangeEmitter(ctrl)
	emitter.EXPECT().Emit(gomock.Any()).Times(2)
	agg := NewScanStateAggregator(engine.GetConfiguration(), engine.GetLogger(), emitter, defaultResolver(engine), engine)

	folder := types.FilePath("/path/folder")
	agg.Init([]types.FilePath{folder})

	agg.SetScanInProgress(folder, product.ProductOpenSource, false)

	snapshot := agg.StateSnapshot()
	assert.True(t, snapshot.AnyScanInProgressWorkingDirectory)
	assert.False(t, snapshot.AnyScanErrorWorkingDirectory)
}

func TestScanStateAggregator_SetScanDone(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingEnableSnykOpenBrowserActions), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)

	ctrl := gomock.NewController(t)
	emitter := NewMockScanStateChangeEmitter(ctrl)
	emitter.EXPECT().Emit(gomock.Any()).Times(4)
	agg := NewScanStateAggregator(engine.GetConfiguration(), engine.GetLogger(), emitter, defaultResolver(engine), engine)

	folder := types.FilePath("/path/folder")
	agg.Init([]types.FilePath{folder})

	agg.SetScanInProgress(folder, product.ProductOpenSource, false)

	agg.SetScanDone(folder, product.ProductOpenSource, false, nil)

	snapshot := agg.StateSnapshot()
	assert.False(t, snapshot.AnyScanErrorWorkingDirectory)
	assert.True(t, snapshot.AnyScanSucceededWorkingDirectory)

	testErr := errors.New("some error")
	agg.SetScanDone(folder, product.ProductCode, false, testErr)

	snapshot = agg.StateSnapshot()
	assert.True(t, snapshot.AnyScanErrorWorkingDirectory)
}

func TestScanStateAggregator_StateSnapshot(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingEnableSnykOpenBrowserActions), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)

	ctrl := gomock.NewController(t)
	emitter := NewMockScanStateChangeEmitter(ctrl)
	emitter.EXPECT().Emit(gomock.Any()).AnyTimes()
	agg := NewScanStateAggregator(engine.GetConfiguration(), engine.GetLogger(), emitter, defaultResolver(engine), engine)

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
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingEnableSnykOpenBrowserActions), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), false)

	ctrl := gomock.NewController(t)
	emitter := NewMockScanStateChangeEmitter(ctrl)
	emitter.EXPECT().Emit(gomock.Any()).Times(5)
	const folderPath = "/path/to/folder"

	agg := NewScanStateAggregator(engine.GetConfiguration(), engine.GetLogger(), emitter, defaultResolver(engine), engine)
	agg.Init([]types.FilePath{folderPath})

	newState := scanState{
		Status: InProgress,
		Err:    nil,
	}

	agg.SetScanState(folderPath, product.ProductOpenSource, false, newState)
	agg.SetScanState(folderPath, product.ProductCode, false, newState)

	agg.SetScanState(folderPath, product.ProductOpenSource, true, newState)
	agg.SetScanState(folderPath, product.ProductCode, true, newState)

	snapshot := agg.StateSnapshot()
	assert.True(t, snapshot.AllScansStartedWorkingDirectory)
	assert.True(t, snapshot.AnyScanInProgressWorkingDirectory)
	assert.Equal(t, snapshot.ScansInProgressCount, 4, "IaC won't be counted since it's disabled")
}

func TestScanStateAggregator_StateSnapshot_ProductScanStates(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingEnableSnykOpenBrowserActions), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), true)

	ctrl := gomock.NewController(t)
	emitter := NewMockScanStateChangeEmitter(ctrl)
	emitter.EXPECT().Emit(gomock.Any()).AnyTimes()
	folder := types.FilePath("/path/folder")

	agg := NewScanStateAggregator(engine.GetConfiguration(), engine.GetLogger(), emitter, defaultResolver(engine), engine)
	agg.Init([]types.FilePath{folder})

	// Set OSS to InProgress, Code to Success, IaC untouched (NotStarted)
	agg.SetScanInProgress(folder, product.ProductOpenSource, false)
	agg.SetScanDone(folder, product.ProductCode, false, nil)

	snapshot := agg.StateSnapshot()

	require.NotNil(t, snapshot.ProductScanStates, "ProductScanStates should be populated")
	folderStates := snapshot.ProductScanStates[folder]
	require.NotNil(t, folderStates, "folder should have scan states")
	assert.True(t, folderStates[product.ProductOpenSource], "OSS should be in progress")
	assert.False(t, folderStates[product.ProductCode], "Code should not be in progress (succeeded)")
	_, iacPresent := folderStates[product.ProductInfrastructureAsCode]
	assert.False(t, iacPresent, "IaC should not be present in scan states (not started)")
}

func TestScanStateAggregator_ProductScanStates_NotStartedProductsExcluded(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingEnableSnykOpenBrowserActions), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), true)

	ctrl := gomock.NewController(t)
	emitter := NewMockScanStateChangeEmitter(ctrl)
	emitter.EXPECT().Emit(gomock.Any()).AnyTimes()
	folder := types.FilePath("/path/folder")

	agg := NewScanStateAggregator(engine.GetConfiguration(), engine.GetLogger(), emitter, defaultResolver(engine), engine)
	agg.Init([]types.FilePath{folder})

	snapshot := agg.StateSnapshot()

	folderStates := snapshot.ProductScanStates[folder]
	assert.Nil(t, folderStates, "no products should be in scan states when all are NotStarted")
}

func TestScanStateAggregator_StateSnapshot_ProductScanErrors(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingEnableSnykOpenBrowserActions), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), true)

	ctrl := gomock.NewController(t)
	emitter := NewMockScanStateChangeEmitter(ctrl)
	emitter.EXPECT().Emit(gomock.Any()).AnyTimes()
	folder := types.FilePath("/path/folder")

	agg := NewScanStateAggregator(engine.GetConfiguration(), engine.GetLogger(), emitter, defaultResolver(engine), engine)
	agg.Init([]types.FilePath{folder})

	// Set OSS to error, Code to success, IaC still not started
	agg.SetScanDone(folder, product.ProductOpenSource, false, errors.New("dependency graph failed"))
	agg.SetScanDone(folder, product.ProductCode, false, nil)

	snapshot := agg.StateSnapshot()

	require.NotNil(t, snapshot.ProductScanErrors, "ProductScanErrors should be populated")
	folderErrors := snapshot.ProductScanErrors[folder]
	require.NotNil(t, folderErrors, "folder should have error entries")
	assert.Equal(t, "dependency graph failed", folderErrors[product.ProductOpenSource], "OSS should have error message")
	_, codeHasError := folderErrors[product.ProductCode]
	assert.False(t, codeHasError, "Code should not have an error")
	_, iacHasError := folderErrors[product.ProductInfrastructureAsCode]
	assert.False(t, iacHasError, "IaC should not have an error (not started)")
}
