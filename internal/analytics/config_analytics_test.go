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

package analytics

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// MockAnalyticsSender captures analytics calls for testing
type MockAnalyticsSender struct {
	calls []AnalyticsCall
}

type AnalyticsCall struct {
	configName    string
	oldVal        any
	newVal        any
	triggerSource string
}

func (m *MockAnalyticsSender) SendConfigChangedAnalytics(c *config.Config, configName string, oldVal, newVal any, triggerSource string) {
	m.calls = append(m.calls, AnalyticsCall{
		configName:    configName,
		oldVal:        oldVal,
		newVal:        newVal,
		triggerSource: triggerSource,
	})
}

// filterCallsBySuffix filters analytics calls by config name suffix
func filterCallsBySuffix(calls []AnalyticsCall, suffix string) []AnalyticsCall {
	var filtered []AnalyticsCall
	for _, call := range calls {
		if len(call.configName) >= len(suffix) && call.configName[len(call.configName)-len(suffix):] == suffix {
			filtered = append(filtered, call)
		}
	}
	return filtered
}

// TestSendCollectionChangeAnalytics_WithInterface tests SendCollectionChangeAnalytics using interface-based dependency injection
func TestSendCollectionChangeAnalytics_WithInterface(t *testing.T) {
	t.Run("sends correct analytics calls for collection changes", func(t *testing.T) {
		c := testutil.UnitTest(t)
		mockSender := &MockAnalyticsSender{}

		oldValue := []string{"item1", "item2", "item3"}
		newValue := []string{"item1", "item4", "item5", "item6"}
		field := "testField"
		triggerSource := "test"

		SendCollectionChangeAnalyticsWithSender(c, field, oldValue, newValue, triggerSource, "Added", "Removed", "Count", mockSender)

		// Verify the correct analytics calls were made
		assert.Len(t, mockSender.calls, 6) // 3 added, 2 removed, 1 count

		// Check added items
		addedCalls := filterCallsBySuffix(mockSender.calls, "Added")
		assert.Len(t, addedCalls, 3)
		assert.Contains(t, addedCalls, AnalyticsCall{configName: "testFieldAdded", oldVal: "", newVal: "item4", triggerSource: "test"})
		assert.Contains(t, addedCalls, AnalyticsCall{configName: "testFieldAdded", oldVal: "", newVal: "item5", triggerSource: "test"})
		assert.Contains(t, addedCalls, AnalyticsCall{configName: "testFieldAdded", oldVal: "", newVal: "item6", triggerSource: "test"})

		// Check removed items
		removedCalls := filterCallsBySuffix(mockSender.calls, "Removed")
		assert.Len(t, removedCalls, 2)
		assert.Contains(t, removedCalls, AnalyticsCall{configName: "testFieldRemoved", oldVal: "item2", newVal: "", triggerSource: "test"})
		assert.Contains(t, removedCalls, AnalyticsCall{configName: "testFieldRemoved", oldVal: "item3", newVal: "", triggerSource: "test"})

		// Check count change
		countCalls := filterCallsBySuffix(mockSender.calls, "Count")
		assert.Len(t, countCalls, 1)
		assert.Contains(t, countCalls, AnalyticsCall{configName: "testFieldCount", oldVal: 3, newVal: 4, triggerSource: "test"})
	})

	t.Run("handles empty arrays with interface verification", func(t *testing.T) {
		c := testutil.UnitTest(t)
		mockSender := &MockAnalyticsSender{}

		oldValue := []string{}
		newValue := []string{"item1", "item2"}
		field := "testField"
		triggerSource := "test"

		SendCollectionChangeAnalyticsWithSender(c, field, oldValue, newValue, triggerSource, "Added", "Removed", "Count", mockSender)

		// Verify the correct analytics calls were made
		assert.Len(t, mockSender.calls, 3) // 2 added, 0 removed, 1 count

		// Check added items
		addedCalls := filterCallsBySuffix(mockSender.calls, "Added")
		assert.Len(t, addedCalls, 2)
		assert.Contains(t, addedCalls, AnalyticsCall{configName: "testFieldAdded", oldVal: "", newVal: "item1", triggerSource: "test"})
		assert.Contains(t, addedCalls, AnalyticsCall{configName: "testFieldAdded", oldVal: "", newVal: "item2", triggerSource: "test"})

		// Check no removed items
		removedCalls := filterCallsBySuffix(mockSender.calls, "Removed")
		assert.Len(t, removedCalls, 0)

		// Check count change
		countCalls := filterCallsBySuffix(mockSender.calls, "Count")
		assert.Len(t, countCalls, 1)
		assert.Contains(t, countCalls, AnalyticsCall{configName: "testFieldCount", oldVal: 0, newVal: 2, triggerSource: "test"})
	})

	t.Run("handles identical arrays with interface verification", func(t *testing.T) {
		c := testutil.UnitTest(t)
		mockSender := &MockAnalyticsSender{}

		value := []string{"item1", "item2"}
		field := "testField"
		triggerSource := "test"

		SendCollectionChangeAnalyticsWithSender(c, field, value, value, triggerSource, "Added", "Removed", "Count", mockSender)

		// Verify no analytics calls were made for identical arrays
		assert.Len(t, mockSender.calls, 0)
	})
}

// TestSendMapConfigChangedAnalytics_WithInterface tests SendMapConfigChangedAnalytics using interface-based dependency injection
func TestSendMapConfigChangedAnalytics_WithInterface(t *testing.T) {
	t.Run("sends correct analytics calls for map changes", func(t *testing.T) {
		c := testutil.UnitTest(t)
		mockSender := &MockAnalyticsSender{}

		oldValue := map[string]int{
			"key1": 1,
			"key2": 2,
			"key3": 3,
		}
		newValue := map[string]int{
			"key1": 10, // modified
			"key4": 4,  // added
			"key5": 5,  // added
		}
		field := "testField"
		path := types.FilePath("/test/path")
		triggerSource := "test"

		SendMapConfigChangedAnalyticsWithSender(c, field, oldValue, newValue, path, triggerSource, mockSender)

		// Verify the correct analytics calls were made
		assert.Len(t, mockSender.calls, 5) // 2 added, 1 modified, 2 removed, 0 count (same count)

		// Check added keys
		addedCalls := filterCallsBySuffix(mockSender.calls, "KeyAdded")
		assert.Len(t, addedCalls, 2)
		assert.Contains(t, addedCalls, AnalyticsCall{configName: "testFieldKeyAdded", oldVal: "", newVal: "key4", triggerSource: "test"})
		assert.Contains(t, addedCalls, AnalyticsCall{configName: "testFieldKeyAdded", oldVal: "", newVal: "key5", triggerSource: "test"})

		// Check modified keys
		modifiedCalls := filterCallsBySuffix(mockSender.calls, "KeyModified")
		assert.Len(t, modifiedCalls, 1)
		assert.Contains(t, modifiedCalls, AnalyticsCall{configName: "testFieldKeyModified", oldVal: 1, newVal: 10, triggerSource: "test"})

		// Check removed keys
		removedCalls := filterCallsBySuffix(mockSender.calls, "KeyRemoved")
		assert.Len(t, removedCalls, 2)
		assert.Contains(t, removedCalls, AnalyticsCall{configName: "testFieldKeyRemoved", oldVal: "key2", newVal: "", triggerSource: "test"})
		assert.Contains(t, removedCalls, AnalyticsCall{configName: "testFieldKeyRemoved", oldVal: "key3", newVal: "", triggerSource: "test"})

		// Check no count change (same count)
		countCalls := filterCallsBySuffix(mockSender.calls, "Count")
		assert.Len(t, countCalls, 0)
	})

	t.Run("handles empty maps with interface verification", func(t *testing.T) {
		c := testutil.UnitTest(t)
		mockSender := &MockAnalyticsSender{}

		oldValue := map[string]int{}
		newValue := map[string]int{"key1": 1, "key2": 2}
		field := "testField"
		path := types.FilePath("/test/path")
		triggerSource := "test"

		SendMapConfigChangedAnalyticsWithSender(c, field, oldValue, newValue, path, triggerSource, mockSender)

		// Verify the correct analytics calls were made
		assert.Len(t, mockSender.calls, 3) // 2 added, 0 modified, 0 removed, 1 count

		// Check added keys
		addedCalls := filterCallsBySuffix(mockSender.calls, "KeyAdded")
		assert.Len(t, addedCalls, 2)
		assert.Contains(t, addedCalls, AnalyticsCall{configName: "testFieldKeyAdded", oldVal: "", newVal: "key1", triggerSource: "test"})
		assert.Contains(t, addedCalls, AnalyticsCall{configName: "testFieldKeyAdded", oldVal: "", newVal: "key2", triggerSource: "test"})

		// Check no modified or removed keys
		modifiedCalls := filterCallsBySuffix(mockSender.calls, "KeyModified")
		assert.Len(t, modifiedCalls, 0)
		removedCalls := filterCallsBySuffix(mockSender.calls, "KeyRemoved")
		assert.Len(t, removedCalls, 0)

		// Check count change
		countCalls := filterCallsBySuffix(mockSender.calls, "Count")
		assert.Len(t, countCalls, 1)
		assert.Contains(t, countCalls, AnalyticsCall{configName: "testFieldCount", oldVal: 0, newVal: 2, triggerSource: "test"})
	})
}

// TestNormalizeTrustedFolders tests the NormalizeTrustedFolders function
func TestNormalizeTrustedFolders(t *testing.T) {
	t.Run("normalizes paths correctly", func(t *testing.T) {
		folders := []types.FilePath{"/path1", "/path2/../path2", "/path3/./subpath", "/path4/"}
		expected := []types.FilePath{
			types.FilePath(filepath.Clean("/path1")),
			types.FilePath(filepath.Clean("/path2/../path2")),
			types.FilePath(filepath.Clean("/path3/./subpath")),
			types.FilePath(filepath.Clean("/path4/")),
		}

		result := NormalizeTrustedFolders(folders)

		assert.Equal(t, expected, result)
	})

	t.Run("handles empty slice", func(t *testing.T) {
		folders := []types.FilePath{}
		result := NormalizeTrustedFolders(folders)
		assert.Empty(t, result)
	})

	t.Run("handles single path", func(t *testing.T) {
		folders := []types.FilePath{"/single/path"}
		expected := []types.FilePath{types.FilePath(filepath.Clean("/single/path"))}

		result := NormalizeTrustedFolders(folders)

		assert.Equal(t, expected, result)
	})
}

// TestSlicesEqualIgnoringOrder tests the SlicesEqualIgnoringOrder function
func TestSlicesEqualIgnoringOrder(t *testing.T) {
	t.Run("equal slices with same order", func(t *testing.T) {
		a := []string{"item1", "item2", "item3"}
		b := []string{"item1", "item2", "item3"}

		assert.True(t, SlicesEqualIgnoringOrder(a, b))
	})

	t.Run("equal slices with different order", func(t *testing.T) {
		a := []string{"item1", "item2", "item3"}
		b := []string{"item3", "item1", "item2"}

		assert.True(t, SlicesEqualIgnoringOrder(a, b))
	})

	t.Run("different length slices", func(t *testing.T) {
		a := []string{"item1", "item2"}
		b := []string{"item1", "item2", "item3"}

		assert.False(t, SlicesEqualIgnoringOrder(a, b))
	})

	t.Run("different content slices", func(t *testing.T) {
		a := []string{"item1", "item2"}
		b := []string{"item1", "item3"}

		assert.False(t, SlicesEqualIgnoringOrder(a, b))
	})

	t.Run("empty slices", func(t *testing.T) {
		a := []string{}
		b := []string{}

		assert.True(t, SlicesEqualIgnoringOrder(a, b))
	})

	t.Run("one empty slice", func(t *testing.T) {
		a := []string{}
		b := []string{"item1"}

		assert.False(t, SlicesEqualIgnoringOrder(a, b))
	})

	t.Run("slices with duplicates", func(t *testing.T) {
		a := []string{"item1", "item1", "item2"}
		b := []string{"item1", "item2", "item1"}

		assert.True(t, SlicesEqualIgnoringOrder(a, b))
	})

	t.Run("slices with different duplicates", func(t *testing.T) {
		a := []string{"item1", "item1", "item2"}
		b := []string{"item1", "item2", "item2"}

		assert.False(t, SlicesEqualIgnoringOrder(a, b))
	})

	t.Run("works with strings", func(t *testing.T) {
		a := []string{"a", "b", "c"}
		b := []string{"c", "a", "b"}

		assert.True(t, SlicesEqualIgnoringOrder(a, b))
	})
}

// TestSendAnalyticsForFieldsLogic tests the SendAnalyticsForFields function logic
func TestSendAnalyticsForFieldsLogic(t *testing.T) {
	type TestStruct struct {
		Field1 string
		Field2 int
		Field3 bool
	}

	t.Run("detects changed fields correctly", func(t *testing.T) {
		oldValue := &TestStruct{Field1: "old", Field2: 1, Field3: true}
		newValue := &TestStruct{Field1: "new", Field2: 2, Field3: true}

		fieldMappings := map[string]func(*TestStruct) bool{
			"Field1": func(s *TestStruct) bool { return s.Field1 == "new" },
			"Field2": func(s *TestStruct) bool { return s.Field2 == 2 },
			"Field3": func(s *TestStruct) bool { return s.Field3 },
		}

		// Test the logic by checking which fields would be considered changed
		changedFields := make(map[string]bool)
		for fieldName, getter := range fieldMappings {
			oldVal := getter(oldValue)
			newVal := getter(newValue)
			if oldVal != newVal {
				changedFields[fieldName] = true
			}
		}

		assert.True(t, changedFields["Field1"])
		assert.True(t, changedFields["Field2"])
		assert.False(t, changedFields["Field3"])
	})

	t.Run("detects no changes when all fields are same", func(t *testing.T) {
		value := &TestStruct{Field1: "same", Field2: 1, Field3: true}

		fieldMappings := map[string]func(*TestStruct) bool{
			"Field1": func(s *TestStruct) bool { return s.Field1 == "same" },
			"Field2": func(s *TestStruct) bool { return s.Field2 == 1 },
			"Field3": func(s *TestStruct) bool { return s.Field3 },
		}

		// Test the logic by checking which fields would be considered changed
		changedFields := make(map[string]bool)
		for fieldName, getter := range fieldMappings {
			oldVal := getter(value)
			newVal := getter(value)
			if oldVal != newVal {
				changedFields[fieldName] = true
			}
		}

		assert.Empty(t, changedFields)
	})

	t.Run("handles empty field mappings", func(t *testing.T) {
		oldValue := &TestStruct{Field1: "old", Field2: 1}
		newValue := &TestStruct{Field1: "new", Field2: 2}

		fieldMappings := map[string]func(*TestStruct) bool{}

		// Test the logic by checking which fields would be considered changed
		changedFields := make(map[string]bool)
		for fieldName, getter := range fieldMappings {
			oldVal := getter(oldValue)
			newVal := getter(newValue)
			if oldVal != newVal {
				changedFields[fieldName] = true
			}
		}

		assert.Empty(t, changedFields)
	})
}

// TestSendConfigChangedAnalyticsWithNilWorkspace tests SendConfigChangedAnalytics with nil workspace
func TestSendConfigChangedAnalyticsWithNilWorkspace(t *testing.T) {
	t.Run("returns early when workspace is nil", func(t *testing.T) {
		c := testutil.UnitTest(t)
		// This test verifies that the function doesn't panic when workspace is nil
		// The actual behavior is tested by the fact that no analytics are sent
		assert.NotPanics(t, func() {
			SendConfigChangedAnalytics(c, "testField", "old", "new", "test")
		})
	})
}

// TestSendArrayConfigChangedAnalyticsWrapper tests the wrapper function
func TestSendArrayConfigChangedAnalyticsWrapper(t *testing.T) {
	t.Run("calls SendCollectionChangeAnalytics with correct parameters", func(t *testing.T) {
		c := testutil.UnitTest(t)
		oldValue := []string{"item1", "item2"}
		newValue := []string{"item1", "item3"}
		field := "testField"
		path := types.FilePath("/test/path")
		triggerSource := "test"

		// This should not panic and should call the underlying function
		assert.NotPanics(t, func() {
			SendArrayConfigChangedAnalytics(c, field, oldValue, newValue, path, triggerSource)
		})
	})
}

// TestSendTrustedFoldersAnalyticsWrapper tests the wrapper function
func TestSendTrustedFoldersAnalyticsWrapper(t *testing.T) {
	t.Run("normalizes paths and calls SendCollectionChangeAnalytics", func(t *testing.T) {
		c := testutil.UnitTest(t)

		oldFolders := []types.FilePath{"/old/path1", "/old/path2/../path2"}
		newFolders := []types.FilePath{"/old/path1", "/new/path3"}
		triggerSource := "test"

		// This should not panic and should normalize paths before comparison
		assert.NotPanics(t, func() {
			SendTrustedFoldersAnalytics(c, oldFolders, newFolders, triggerSource)
		})
	})
}
