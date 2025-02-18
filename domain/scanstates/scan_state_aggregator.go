/*
 * © 2025 Snyk Limited
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

package scanstates

import (
	"sync"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

var _ Aggregator = (*ScanStateAggregator)(nil)

// folderProductKey identifies a unique (FolderPath, ProductName) pair.
type folderProductKey struct {
	FolderPath types.FilePath
	Product    product.Product
}

type scanStatus string

const (
	NotStarted scanStatus = "NOT_STARTED"
	InProgress scanStatus = "IN_PROGRESS"
	Success    scanStatus = "SUCCESS"
	Error      scanStatus = "ERROR"
)

// scanState describes the state for one scan (per folder+product).
type scanState struct {
	Status scanStatus
	Err    error
}

type scanStateMap map[folderProductKey]*scanState

// ScanStateAggregator stores and manages the scan states for working directory and reference scans.
type ScanStateAggregator struct {
	mu                         sync.RWMutex
	referenceScanStates        scanStateMap
	workingDirectoryScanStates scanStateMap
	scanStateChangeEmitter     ScanStateChangeEmitter
	c                          *config.Config
}

type StateSnapshot struct {
	AllScansStartedReference          bool
	AllScansStartedWorkingDirectory   bool
	AnyScanInProgressReference        bool
	AnyScanInProgressWorkingDirectory bool
	AnyScanSucceededReference         bool
	AnyScanSucceededWorkingDirectory  bool
	AllScansSucceededReference        bool
	AllScansSucceededWorkingDirectory bool
	AnyScanErrorReference             bool
	AnyScanErrorWorkingDirectory      bool
	AllScansFinishedWorkingDirectory  bool
	AllScansFinishedReference         bool
	TotalScansCount                   int
	ScansInProgressCount              int
	ScansErrorCount                   int
	ScansSuccessCount                 int
}

func (agg *ScanStateAggregator) StateSnapshot() StateSnapshot {
	agg.mu.RLock()
	defer agg.mu.RUnlock()

	return agg.stateSnapshot()
}

func (agg *ScanStateAggregator) stateSnapshot() StateSnapshot {
	ss := StateSnapshot{
		AllScansStartedReference:          agg.allScansStarted(true),
		AllScansStartedWorkingDirectory:   agg.allScansStarted(false),
		AnyScanInProgressReference:        agg.anyScanInProgress(true),
		AnyScanInProgressWorkingDirectory: agg.anyScanInProgress(false),
		AnyScanSucceededReference:         agg.anyScanSucceeded(true),
		AnyScanSucceededWorkingDirectory:  agg.anyScanSucceeded(false),
		AllScansSucceededReference:        agg.allScansSucceeded(true),
		AllScansSucceededWorkingDirectory: agg.allScansSucceeded(false),
		AnyScanErrorReference:             agg.anyScanError(true),
		AnyScanErrorWorkingDirectory:      agg.anyScanError(false),
		TotalScansCount:                   agg.totalScansCount(),
		ScansInProgressCount:              agg.scansCountInState(InProgress),
		ScansSuccessCount:                 agg.scansCountInState(Success),
		ScansErrorCount:                   agg.scansCountInState(Error),
		AllScansFinishedWorkingDirectory:  agg.allScansFinished(false),
		AllScansFinishedReference:         agg.allScansFinished(true),
	}
	return ss
}

func (agg *ScanStateAggregator) SummaryEmitter() ScanStateChangeEmitter {
	return agg.scanStateChangeEmitter
}

// NewScanStateAggregator constructs a new scanstates.
func NewScanStateAggregator(c *config.Config, ssce ScanStateChangeEmitter) Aggregator {
	return &ScanStateAggregator{
		referenceScanStates:        make(scanStateMap),
		workingDirectoryScanStates: make(scanStateMap),
		scanStateChangeEmitter:     ssce,
		c:                          c,
	}
}

func (agg *ScanStateAggregator) Init(folders []types.FilePath) {
	agg.mu.Lock()
	defer agg.mu.Unlock()

	for _, f := range folders {
		agg.initForAllProducts(f)
	}
	// Emit after init to send first summary
	agg.scanStateChangeEmitter.Emit(agg.stateSnapshot())
}

func (agg *ScanStateAggregator) initForAllProducts(folderPath types.FilePath) {
	// TODO: Add or remove from the map if a product is on/off
	agg.referenceScanStates[folderProductKey{Product: product.ProductOpenSource, FolderPath: folderPath}] = &scanState{Status: NotStarted}
	agg.referenceScanStates[folderProductKey{Product: product.ProductCode, FolderPath: folderPath}] = &scanState{Status: NotStarted}
	agg.referenceScanStates[folderProductKey{Product: product.ProductInfrastructureAsCode, FolderPath: folderPath}] = &scanState{Status: NotStarted}

	agg.workingDirectoryScanStates[folderProductKey{Product: product.ProductOpenSource, FolderPath: folderPath}] = &scanState{Status: NotStarted}
	agg.workingDirectoryScanStates[folderProductKey{Product: product.ProductCode, FolderPath: folderPath}] = &scanState{Status: NotStarted}
	agg.workingDirectoryScanStates[folderProductKey{Product: product.ProductInfrastructureAsCode, FolderPath: folderPath}] = &scanState{Status: NotStarted}
}

// AddNewFolder adds new folder to the state scanstates map with initial NOT_STARTED state
func (agg *ScanStateAggregator) AddNewFolder(folderPath types.FilePath) {
	agg.mu.Lock()
	defer agg.mu.Unlock()

	agg.initForAllProducts(folderPath)

	agg.scanStateChangeEmitter.Emit(agg.stateSnapshot())
}

// SetScanState changes the Status field of the existing state (or creates it if it doesn't exist).
func (agg *ScanStateAggregator) SetScanState(folderPath types.FilePath, p product.Product, isReferenceScan bool, newState scanState) {
	agg.mu.Lock()
	defer agg.mu.Unlock()

	agg.setScanState(folderPath, p, isReferenceScan, newState)
}

func (agg *ScanStateAggregator) setScanState(folderPath types.FilePath, p product.Product, isReferenceScan bool, newState scanState) {
	logger := agg.c.Logger().With().Str("method", "SetScanState").Logger()

	key := folderProductKey{FolderPath: folderPath, Product: p}
	var st *scanState
	var exists bool
	if isReferenceScan {
		st, exists = agg.referenceScanStates[key]
	} else {
		st, exists = agg.workingDirectoryScanStates[key]
	}

	if !exists {
		logger.Error().Msgf("Scan State for folder path%s and product %s doesn't exist in state scanstates", folderPath, p.ToProductNamesString())
		return
	}

	st.Status = newState.Status
	st.Err = newState.Err

	agg.scanStateChangeEmitter.Emit(agg.stateSnapshot())
}

func (agg *ScanStateAggregator) SetScanDone(folderPath types.FilePath, p product.Product, isReferenceScan bool, scanErr error) {
	agg.mu.Lock()
	defer agg.mu.Unlock()

	state := scanState{}
	if scanErr != nil {
		state.Status = Error
		state.Err = scanErr
	} else {
		state.Status = Success
	}

	agg.setScanState(folderPath, p, isReferenceScan, state)
}

func (agg *ScanStateAggregator) GetScanErr(folderPath types.FilePath, p product.Product, isReferenceScan bool) error {
	agg.mu.RLock()
	defer agg.mu.RUnlock()

	logger := agg.c.Logger().With().Str("method", "GetScanErr").Logger()

	key := folderProductKey{FolderPath: folderPath, Product: p}
	var st *scanState
	var exists bool
	if isReferenceScan {
		st, exists = agg.referenceScanStates[key]
	} else {
		st, exists = agg.workingDirectoryScanStates[key]
	}

	if !exists {
		logger.Error().Msgf("Scan State for folder path%s and product %s doesn't exist in state scanstates", folderPath, p.ToProductNamesString())
		return nil
	}

	return st.Err
}

func (agg *ScanStateAggregator) SetScanInProgress(folderPath types.FilePath, p product.Product, isReferenceScan bool) {
	agg.mu.Lock()
	defer agg.mu.Unlock()

	state := scanState{
		Status: InProgress,
	}

	agg.setScanState(folderPath, p, isReferenceScan, state)
}

func (agg *ScanStateAggregator) allScansStarted(isReference bool) bool {
	return agg.allMatch(isReference, func(st *scanState) bool {
		return st.Status != NotStarted
	})
}

func (agg *ScanStateAggregator) anyScanInProgress(isReference bool) bool {
	return agg.anyMatch(isReference, func(st *scanState) bool {
		return st.Status == InProgress
	})
}

func (agg *ScanStateAggregator) anyScanSucceeded(isReference bool) bool {
	return agg.anyMatch(isReference, func(st *scanState) bool {
		return st.Status == Success
	})
}

func (agg *ScanStateAggregator) allScansSucceeded(isReference bool) bool {
	return agg.allMatch(isReference, func(st *scanState) bool {
		return st.Status == Success && st.Err == nil
	})
}

func (agg *ScanStateAggregator) allScansFinished(isReference bool) bool {
	return agg.allMatch(isReference, func(st *scanState) bool { return st.Status == Success || st.Status == Error })
}

func (agg *ScanStateAggregator) anyScanError(isReference bool) bool {
	return agg.anyMatch(isReference, func(st *scanState) bool {
		return st.Status == Error
	})
}

func (agg *ScanStateAggregator) totalScansCount() int {
	scansCount := len(agg.scanStateForEnabledProducts(false)) + len(agg.scanStateForEnabledProducts(true))
	return scansCount
}

func (agg *ScanStateAggregator) scansCountInState(status scanStatus) int {
	count := 0
	wdStateMap := agg.scanStateForEnabledProducts(false)
	refStateMap := agg.scanStateForEnabledProducts(true)

	for _, st := range wdStateMap {
		if st.Status == status {
			count++
		}
	}
	for _, st := range refStateMap {
		if st.Status == status {
			count++
		}
	}

	return count
}

func (agg *ScanStateAggregator) anyMatch(isReference bool, predicate func(*scanState) bool) bool {
	stateMap := agg.scanStateForEnabledProducts(isReference)

	for _, st := range stateMap {
		if predicate(st) {
			return true
		}
	}
	return false
}

func (agg *ScanStateAggregator) allMatch(isReference bool, predicate func(*scanState) bool) bool {
	stateMap := agg.scanStateForEnabledProducts(isReference)

	for _, st := range stateMap {
		if !predicate(st) {
			return false
		}
	}
	return true
}

func (agg *ScanStateAggregator) scanStateForEnabledProducts(isReference bool) scanStateMap {
	var stateMap scanStateMap
	if isReference {
		stateMap = agg.referenceScanStates
	} else {
		stateMap = agg.workingDirectoryScanStates
	}
	scanStateMapWithEnabledProducts := make(scanStateMap)

	for key, st := range stateMap {
		for displayableIssueType, enabled := range agg.c.DisplayableIssueTypes() {
			p := displayableIssueType.ToProduct()
			if enabled && key.Product == p {
				scanStateMapWithEnabledProducts[key] = st
				break
			}
		}
	}

	return scanStateMapWithEnabledProducts
}
