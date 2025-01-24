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
)

// FolderProductKey identifies a unique (FolderPath, ProductName) pair.
type FolderProductKey struct {
	FolderPath string
	Product    product.Product
}

type ScanStatus string

const (
	NotStarted ScanStatus = "NOT_STARTED"
	InProgress ScanStatus = "IN_PROGRESS"
	Success    ScanStatus = "SUCCESS"
	Error      ScanStatus = "ERROR"
)

// ScanState describes the state for one scan (per folder+product).
type ScanState struct {
	Status ScanStatus
	Err    error
}

type ScanStateMap map[FolderProductKey]*ScanState

// ScanStateAggregator stores and manages the scan states for working directory and reference scans.
type ScanStateAggregator struct {
	mu                         sync.RWMutex
	referenceScanStates        ScanStateMap
	workingDirectoryScanStates ScanStateMap
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
	}
	return ss
}

func (agg *ScanStateAggregator) SummaryEmitter() ScanStateChangeEmitter {
	return agg.scanStateChangeEmitter
}

// NewScanStateAggregator constructs a new scanstates.
func NewScanStateAggregator(c *config.Config, ssce ScanStateChangeEmitter) Aggregator {
	return &ScanStateAggregator{
		referenceScanStates:        make(ScanStateMap),
		workingDirectoryScanStates: make(ScanStateMap),
		scanStateChangeEmitter:     ssce,
		c:                          c,
	}
}

func (agg *ScanStateAggregator) Init(folders []string) {
	agg.mu.Lock()
	defer agg.mu.Unlock()

	for _, f := range folders {
		agg.initForAllProducts(f)
	}
	// Emit after init to send first summary
	agg.scanStateChangeEmitter.Emit(agg.stateSnapshot())
}

func (agg *ScanStateAggregator) initForAllProducts(folderPath string) {
	// TODO: Add or remove from the map if a product is on/off
	agg.referenceScanStates[FolderProductKey{Product: product.ProductOpenSource, FolderPath: folderPath}] = &ScanState{Status: NotStarted}
	agg.referenceScanStates[FolderProductKey{Product: product.ProductCode, FolderPath: folderPath}] = &ScanState{Status: NotStarted}
	agg.referenceScanStates[FolderProductKey{Product: product.ProductInfrastructureAsCode, FolderPath: folderPath}] = &ScanState{Status: NotStarted}

	agg.workingDirectoryScanStates[FolderProductKey{Product: product.ProductOpenSource, FolderPath: folderPath}] = &ScanState{Status: NotStarted}
	agg.workingDirectoryScanStates[FolderProductKey{Product: product.ProductCode, FolderPath: folderPath}] = &ScanState{Status: NotStarted}
	agg.workingDirectoryScanStates[FolderProductKey{Product: product.ProductInfrastructureAsCode, FolderPath: folderPath}] = &ScanState{Status: NotStarted}
}

// AddNewFolder adds new folder to the state scanstates map with initial NOT_STARTED state
func (agg *ScanStateAggregator) AddNewFolder(folderPath string) {
	agg.mu.Lock()
	defer agg.mu.Unlock()

	agg.initForAllProducts(folderPath)

	agg.scanStateChangeEmitter.Emit(agg.stateSnapshot())
}

// SetScanState changes the Status field of the existing state (or creates it if it doesn't exist).
func (agg *ScanStateAggregator) SetScanState(folderPath string, p product.Product, isReferenceScan bool, newState ScanState) {
	agg.mu.Lock()
	defer agg.mu.Unlock()

	agg.setScanState(folderPath, p, isReferenceScan, newState)
}

func (agg *ScanStateAggregator) setScanState(folderPath string, p product.Product, isReferenceScan bool, newState ScanState) {
	logger := agg.c.Logger().With().Str("method", "SetScanState").Logger()

	key := FolderProductKey{FolderPath: folderPath, Product: p}
	var st *ScanState
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

func (agg *ScanStateAggregator) SetScanDone(folderPath string, p product.Product, isReferenceScan bool, scanErr error) {
	agg.mu.Lock()
	defer agg.mu.Unlock()

	state := ScanState{}
	if scanErr != nil {
		state.Status = Error
		state.Err = scanErr
	} else {
		state.Status = Success
	}

	agg.setScanState(folderPath, p, isReferenceScan, state)
}

func (agg *ScanStateAggregator) SetScanInProgress(folderPath string, p product.Product, isReferenceScan bool) {
	agg.mu.Lock()
	defer agg.mu.Unlock()

	state := ScanState{
		Status: InProgress,
	}

	agg.setScanState(folderPath, p, isReferenceScan, state)
}

func (agg *ScanStateAggregator) allScansStarted(isReference bool) bool {
	return agg.allMatch(isReference, func(st *ScanState) bool {
		return st.Status != NotStarted
	})
}

func (agg *ScanStateAggregator) anyScanInProgress(isReference bool) bool {
	return agg.anyMatch(isReference, func(st *ScanState) bool {
		return st.Status == InProgress
	})
}

func (agg *ScanStateAggregator) anyScanSucceeded(isReference bool) bool {
	return agg.anyMatch(isReference, func(st *ScanState) bool {
		return st.Status == Success
	})
}

func (agg *ScanStateAggregator) allScansSucceeded(isReference bool) bool {
	return agg.allMatch(isReference, func(st *ScanState) bool {
		return st.Status == Success && st.Err == nil
	})
}

func (agg *ScanStateAggregator) anyScanError(isReference bool) bool {
	return agg.anyMatch(isReference, func(st *ScanState) bool {
		return st.Status == Error
	})
}

func (agg *ScanStateAggregator) totalScansCount() int {
	scansCount := len(agg.referenceScanStates) + len(agg.workingDirectoryScanStates)
	return scansCount
}

func (agg *ScanStateAggregator) scansCountInState(status ScanStatus) int {
	count := 0

	for _, st := range agg.workingDirectoryScanStates {
		if st.Status == status {
			count++
		}
	}
	for _, st := range agg.referenceScanStates {
		if st.Status == status {
			count++
		}
	}

	return count
}

func (agg *ScanStateAggregator) anyMatch(isReference bool, predicate func(*ScanState) bool) bool {
	var stateMap ScanStateMap
	if isReference {
		stateMap = agg.referenceScanStates
	} else {
		stateMap = agg.workingDirectoryScanStates
	}

	for _, st := range stateMap {
		if predicate(st) {
			return true
		}
	}
	return false
}

func (agg *ScanStateAggregator) allMatch(isReference bool, predicate func(*ScanState) bool) bool {
	var stateMap ScanStateMap
	if isReference {
		stateMap = agg.referenceScanStates
	} else {
		stateMap = agg.workingDirectoryScanStates
	}

	for _, st := range stateMap {
		if !predicate(st) {
			return false
		}
	}
	return true
}
