/*
 * © 2026 Snyk Limited
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

package treeview

import "sync"

// ExpandState tracks user-controlled expand/collapse state for tree view nodes.
// State is persisted across re-renders so that the tree retains its
// expand/collapse positions when the LS pushes new HTML.
type ExpandState struct {
	mu    sync.RWMutex
	state map[string]bool
}

// globalExpandState is the package-level singleton used by emitters and commands.
// Tests should create their own via NewExpandState() for isolation.
var globalExpandState = NewExpandState()

// GlobalExpandState returns the shared expand state used across the tree view pipeline.
func GlobalExpandState() *ExpandState {
	return globalExpandState
}

// NewExpandState creates a new empty expand state.
func NewExpandState() *ExpandState {
	return &ExpandState{
		state: make(map[string]bool),
	}
}

// Set records the expanded state for a node.
func (es *ExpandState) Set(nodeID string, expanded bool) {
	es.mu.Lock()
	defer es.mu.Unlock()
	es.state[nodeID] = expanded
}

// Clear removes all stored expand/collapse state.
func (es *ExpandState) Clear() {
	es.mu.Lock()
	defer es.mu.Unlock()
	es.state = make(map[string]bool)
}

// Get returns the stored expanded state for a node and whether it was set.
func (es *ExpandState) Get(nodeID string) (expanded bool, ok bool) {
	es.mu.RLock()
	defer es.mu.RUnlock()
	expanded, ok = es.state[nodeID]
	return
}

// PruneExcept removes all entries whose keys are not in the activeIDs set.
// Call this after building the tree to remove stale entries from removed folders/files.
func (es *ExpandState) PruneExcept(activeIDs map[string]bool) {
	es.mu.Lock()
	defer es.mu.Unlock()
	for id := range es.state {
		if !activeIDs[id] {
			delete(es.state, id)
		}
	}
}

// IsExpanded returns whether a node should be expanded, applying the stored
// override if present, or falling back to a default based on node type.
// Defaults: folder=true, product=true, file=false, issue=false, info=false.
func (es *ExpandState) IsExpanded(nodeID string, nodeType NodeType) bool {
	es.mu.RLock()
	expanded, ok := es.state[nodeID]
	es.mu.RUnlock()
	if ok {
		return expanded
	}
	return defaultExpanded(nodeType)
}

func defaultExpanded(nodeType NodeType) bool {
	switch nodeType {
	case NodeTypeFolder, NodeTypeProduct:
		return true
	default:
		return false
	}
}
