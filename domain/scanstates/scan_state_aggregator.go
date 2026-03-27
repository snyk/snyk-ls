/*
 * © 2025-2026 Snyk Limited
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
	configResolver             types.ConfigResolverInterface
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
	// ProductScanStates maps each (folder, product) pair to whether a working-directory scan is in progress.
	ProductScanStates map[types.FilePath]map[product.Product]bool
	// ProductScanErrors maps each (folder, product) pair to its error message for failed working-directory scans.
	ProductScanErrors map[types.FilePath]map[product.Product]string
}

func (agg *ScanStateAggregator) StateSnapshot() StateSnapshot {
	agg.mu.RLock()
	defer agg.mu.RUnlock()

	return agg.stateSnapshot()
}

func (agg *ScanStateAggregator) stateSnapshot() StateSnapshot {
	refStateMap := agg.scanStateForEnabledProducts(true)
	wdStateMap := agg.scanStateForEnabledProducts(false)

	ss := StateSnapshot{
		AllScansStartedReference:          agg.allScansStarted(refStateMap),
		AllScansStartedWorkingDirectory:   agg.allScansStarted(wdStateMap),
		AnyScanInProgressReference:        agg.anyScanInProgress(refStateMap),
		AnyScanInProgressWorkingDirectory: agg.anyScanInProgress(wdStateMap),
		AnyScanSucceededReference:         agg.anyScanSucceeded(refStateMap),
		AnyScanSucceededWorkingDirectory:  agg.anyScanSucceeded(wdStateMap),
		AllScansSucceededReference:        agg.allScansSucceeded(refStateMap),
		AllScansSucceededWorkingDirectory: agg.allScansSucceeded(wdStateMap),
		AnyScanErrorReference:             agg.anyScanError(refStateMap),
		AnyScanErrorWorkingDirectory:      agg.anyScanError(wdStateMap),
		TotalScansCount:                   agg.totalScansCount(wdStateMap, refStateMap),
		ScansInProgressCount:              agg.scansCountInState(wdStateMap, refStateMap, InProgress),
		ScansSuccessCount:                 agg.scansCountInState(wdStateMap, refStateMap, Success),
		ScansErrorCount:                   agg.scansCountInState(wdStateMap, refStateMap, Error),
		AllScansFinishedWorkingDirectory:  agg.allScansFinished(wdStateMap),
		AllScansFinishedReference:         agg.allScansFinished(refStateMap),
		ProductScanStates:                 agg.productScanStates(wdStateMap),
		ProductScanErrors:                 agg.productScanErrors(wdStateMap),
	}
	return ss
}

// productScanStates builds a per-(folder, product) map of whether a working-directory scan is in progress.
// Only products that have actually started scanning are included; NotStarted products are omitted
// so the tree builder can distinguish "not yet scanned" from "scan completed with 0 issues".
func (agg *ScanStateAggregator) productScanStates(stateMap scanStateMap) map[types.FilePath]map[product.Product]bool {
	states := make(map[types.FilePath]map[product.Product]bool)
	for key, st := range stateMap {
		if st.Status == NotStarted {
			continue
		}
		if states[key.FolderPath] == nil {
			states[key.FolderPath] = make(map[product.Product]bool)
		}
		if st.Status == InProgress {
			states[key.FolderPath][key.Product] = true
		} else if _, exists := states[key.FolderPath][key.Product]; !exists {
			states[key.FolderPath][key.Product] = false
		}
	}
	return states
}

// productScanErrors builds a per-(folder, product) map of error messages for working-directory scans that ended in error.
func (agg *ScanStateAggregator) productScanErrors(stateMap scanStateMap) map[types.FilePath]map[product.Product]string {
	errs := make(map[types.FilePath]map[product.Product]string)
	for key, st := range stateMap {
		if st.Status == Error && st.Err != nil {
			if errs[key.FolderPath] == nil {
				errs[key.FolderPath] = make(map[product.Product]string)
			}
			errs[key.FolderPath][key.Product] = st.Err.Error()
		}
	}
	return errs
}

func (agg *ScanStateAggregator) SummaryEmitter() ScanStateChangeEmitter {
	return agg.scanStateChangeEmitter
}

// NewScanStateAggregator constructs a new scanstates.
func NewScanStateAggregator(c *config.Config, ssce ScanStateChangeEmitter, configResolver types.ConfigResolverInterface) Aggregator {
	return &ScanStateAggregator{
		referenceScanStates:        make(scanStateMap),
		workingDirectoryScanStates: make(scanStateMap),
		scanStateChangeEmitter:     ssce,
		c:                          c,
		configResolver:             configResolver,
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
	agg.referenceScanStates[folderProductKey{Product: product.ProductSecrets, FolderPath: folderPath}] = &scanState{Status: NotStarted}

	agg.workingDirectoryScanStates[folderProductKey{Product: product.ProductOpenSource, FolderPath: folderPath}] = &scanState{Status: NotStarted}
	agg.workingDirectoryScanStates[folderProductKey{Product: product.ProductCode, FolderPath: folderPath}] = &scanState{Status: NotStarted}
	agg.workingDirectoryScanStates[folderProductKey{Product: product.ProductInfrastructureAsCode, FolderPath: folderPath}] = &scanState{Status: NotStarted}
	agg.workingDirectoryScanStates[folderProductKey{Product: product.ProductSecrets, FolderPath: folderPath}] = &scanState{Status: NotStarted}
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

func (agg *ScanStateAggregator) allScansStarted(stateMap scanStateMap) bool {
	return agg.allMatch(stateMap, func(st *scanState) bool {
		return st.Status != NotStarted
	})
}

func (agg *ScanStateAggregator) anyScanInProgress(stateMap scanStateMap) bool {
	return agg.anyMatch(stateMap, func(st *scanState) bool {
		return st.Status == InProgress
	})
}

func (agg *ScanStateAggregator) anyScanSucceeded(stateMap scanStateMap) bool {
	return agg.anyMatch(stateMap, func(st *scanState) bool {
		return st.Status == Success
	})
}

func (agg *ScanStateAggregator) allScansSucceeded(stateMap scanStateMap) bool {
	return agg.allMatch(stateMap, func(st *scanState) bool {
		return st.Status == Success && st.Err == nil
	})
}

func (agg *ScanStateAggregator) allScansFinished(stateMap scanStateMap) bool {
	return agg.allMatch(stateMap, func(st *scanState) bool { return st.Status == Success || st.Status == Error })
}

func (agg *ScanStateAggregator) anyScanError(stateMap scanStateMap) bool {
	return agg.anyMatch(stateMap, func(st *scanState) bool {
		return st.Status == Error
	})
}

func (agg *ScanStateAggregator) totalScansCount(wdStateMap, refStateMap scanStateMap) int {
	scansCount := len(wdStateMap) + len(refStateMap)
	return scansCount
}

func (agg *ScanStateAggregator) scansCountInState(wdStateMap, refStateMap scanStateMap, status scanStatus) int {
	count := 0

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

func (agg *ScanStateAggregator) anyMatch(stateMap scanStateMap, predicate func(*scanState) bool) bool {
	for _, st := range stateMap {
		if predicate(st) {
			return true
		}
	}
	return false
}

func (agg *ScanStateAggregator) allMatch(stateMap scanStateMap, predicate func(*scanState) bool) bool {
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
		folderConfig := agg.c.ImmutableFolderConfig(key.FolderPath)
		issueTypes := agg.displayableIssueTypesForFolder(folderConfig)
		for displayableIssueType, enabled := range issueTypes {
			p := displayableIssueType.ToProduct()
			if enabled && key.Product == p {
				scanStateMapWithEnabledProducts[key] = st
				break
			}
		}
	}

	return scanStateMapWithEnabledProducts
}

func (agg *ScanStateAggregator) displayableIssueTypesForFolder(folderConfig types.ImmutableFolderConfig) map[product.FilterableIssueType]bool {
	return types.ResolveDisplayableIssueTypes(agg.configResolver, agg.c, folderConfig)
}
