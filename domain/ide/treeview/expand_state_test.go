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

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExpandState_SetAndGet(t *testing.T) {
	es := NewExpandState()
	es.Set("node-1", true)
	es.Set("node-2", false)

	expanded, ok := es.Get("node-1")
	assert.True(t, ok)
	assert.True(t, expanded)

	expanded, ok = es.Get("node-2")
	assert.True(t, ok)
	assert.False(t, expanded)
}

func TestExpandState_Get_UnknownNode_ReturnsNotFound(t *testing.T) {
	es := NewExpandState()

	_, ok := es.Get("unknown-node")
	assert.False(t, ok, "unset node should return not found")
}

func TestExpandState_IsExpanded_DefaultsByNodeType(t *testing.T) {
	es := NewExpandState()

	assert.True(t, es.IsExpanded("any-folder", NodeTypeFolder), "folder default = expanded")
	assert.True(t, es.IsExpanded("any-product", NodeTypeProduct), "product default = expanded")
	assert.False(t, es.IsExpanded("any-file", NodeTypeFile), "file default = collapsed")
	assert.False(t, es.IsExpanded("any-issue", NodeTypeIssue), "issue default = collapsed")
	assert.False(t, es.IsExpanded("any-info", NodeTypeInfo), "info default = collapsed")
}

func TestExpandState_IsExpanded_OverridesDefault(t *testing.T) {
	es := NewExpandState()
	es.Set("my-folder", false)
	es.Set("my-file", true)

	assert.False(t, es.IsExpanded("my-folder", NodeTypeFolder), "explicitly collapsed folder")
	assert.True(t, es.IsExpanded("my-file", NodeTypeFile), "explicitly expanded file")
}

func TestExpandState_PruneExcept_RemovesStaleEntries(t *testing.T) {
	es := NewExpandState()
	es.Set("folder:a", true)
	es.Set("folder:b", false)
	es.Set("file:c", true)

	activeIDs := map[string]bool{"folder:a": true, "file:c": true}
	es.PruneExcept(activeIDs)

	_, ok := es.Get("folder:b")
	assert.False(t, ok, "pruned node should be removed")

	expanded, ok := es.Get("folder:a")
	assert.True(t, ok)
	assert.True(t, expanded)

	expanded, ok = es.Get("file:c")
	assert.True(t, ok)
	assert.True(t, expanded)
}

func TestExpandState_PruneExcept_EmptyActiveSet_ClearsAll(t *testing.T) {
	es := NewExpandState()
	es.Set("folder:a", true)
	es.Set("folder:b", false)

	es.PruneExcept(map[string]bool{})

	_, ok := es.Get("folder:a")
	assert.False(t, ok)
	_, ok = es.Get("folder:b")
	assert.False(t, ok)
}

func TestExpandState_ConcurrentAccess(t *testing.T) {
	es := NewExpandState()
	done := make(chan struct{})

	go func() {
		for i := 0; i < 100; i++ {
			es.Set("node-a", true)
		}
		done <- struct{}{}
	}()

	go func() {
		for i := 0; i < 100; i++ {
			es.IsExpanded("node-a", NodeTypeFolder)
		}
		done <- struct{}{}
	}()

	<-done
	<-done
}
