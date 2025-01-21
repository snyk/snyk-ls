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

package aggregator

import (
	"sync"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
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
	Done       ScanStatus = "DONE"
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

// NewScanStateAggregator constructs a new aggregator.
func NewScanStateAggregator(ssce ScanStateChangeEmitter, ws *workspace.Workspace, c *config.Config) *ScanStateAggregator {
	res := &ScanStateAggregator{
		referenceScanStates:        make(ScanStateMap),
		workingDirectoryScanStates: make(ScanStateMap),
		scanStateChangeEmitter:     ssce,
		c:                          c,
	}
	for _, f := range ws.Folders() {
		res.referenceScanStates[FolderProductKey{Product: product.ProductOpenSource, FolderPath: f.Path()}] = &ScanState{Status: NotStarted}
		res.referenceScanStates[FolderProductKey{Product: product.ProductCode, FolderPath: f.Path()}] = &ScanState{Status: NotStarted}
		res.referenceScanStates[FolderProductKey{Product: product.ProductInfrastructureAsCode, FolderPath: f.Path()}] = &ScanState{Status: NotStarted}

		res.workingDirectoryScanStates[FolderProductKey{Product: product.ProductOpenSource, FolderPath: f.Path()}] = &ScanState{Status: NotStarted}
		res.workingDirectoryScanStates[FolderProductKey{Product: product.ProductCode, FolderPath: f.Path()}] = &ScanState{Status: NotStarted}
		res.workingDirectoryScanStates[FolderProductKey{Product: product.ProductInfrastructureAsCode, FolderPath: f.Path()}] = &ScanState{Status: NotStarted}
	}

	return res
}

// SetScanState changes the Status field of the existing state (or creates it if it doesn't exist).
func (agg *ScanStateAggregator) SetScanState(folderPath string, p product.Product, isReferenceScan bool, newState ScanState) {
	agg.mu.Lock()
	defer agg.mu.Unlock()

	key := FolderProductKey{FolderPath: folderPath, Product: p}
	var st *ScanState
	var exists bool
	if isReferenceScan {
		st, exists = agg.referenceScanStates[key]
	} else {
		st, exists = agg.workingDirectoryScanStates[key]
	}

	if !exists {
		agg.c.Logger().Error().Msgf("Scan State for folder path%s and product %s doesn't exist in state aggregator", folderPath, p.ToProductNamesString())
		return
	}

	st.Status = newState.Status
	st.Err = newState.Err

	agg.scanStateChangeEmitter.Emit()
}

func (agg *ScanStateAggregator) AreAllScansNotStarted(isReference bool) bool {
	agg.mu.RLock()
	defer agg.mu.RUnlock()

	var stateMap ScanStateMap
	if isReference {
		stateMap = agg.referenceScanStates
	} else {
		stateMap = agg.workingDirectoryScanStates
	}

	for _, st := range stateMap {
		if st.Status != NotStarted {
			return false
		}
	}
	return true
}

func (agg *ScanStateAggregator) HasAnyScanInProgress(isReference bool) bool {
	agg.mu.RLock()
	defer agg.mu.RUnlock()

	var stateMap ScanStateMap
	if isReference {
		stateMap = agg.referenceScanStates
	} else {
		stateMap = agg.workingDirectoryScanStates
	}

	for _, st := range stateMap {
		if st.Status == InProgress {
			return true
		}
	}
	return false
}

func (agg *ScanStateAggregator) HaveAllScansSucceeded(isReference bool) bool {
	agg.mu.RLock()
	defer agg.mu.RUnlock()

	var stateMap ScanStateMap
	if isReference {
		stateMap = agg.referenceScanStates
	} else {
		stateMap = agg.workingDirectoryScanStates
	}

	for _, st := range stateMap {
		if st.Status != Done || st.Err != nil {
			return false
		}
	}
	return true
}

func (agg *ScanStateAggregator) HasAnyScanError(isReference bool) bool {
	agg.mu.RLock()
	defer agg.mu.RUnlock()

	var stateMap ScanStateMap
	if isReference {
		stateMap = agg.referenceScanStates
	} else {
		stateMap = agg.workingDirectoryScanStates
	}

	for _, st := range stateMap {
		if st.Status == Error {
			return true
		}
	}
	return false
}
