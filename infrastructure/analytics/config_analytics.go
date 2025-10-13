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
	"cmp"
	"reflect"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

// SendConfigChangedAnalytics sends analytics for primitive values only
func SendConfigChangedAnalytics(c *config.Config, configName string, oldVal any, newVal any, triggerSource string) {
	// Don't send analytics if old and new values are identical
	if oldVal == newVal {
		return
	}

	ws := c.Workspace()
	if ws == nil {
		return
	}

	for _, folder := range ws.Folders() {
		go SendConfigChangedAnalyticsEvent(c, configName, oldVal, newVal, folder.Path(), triggerSource)
	}
}

// SendConfigChangedAnalyticsEvent sends a single analytics event for a config change
func SendConfigChangedAnalyticsEvent(c *config.Config, field string, oldValue, newValue interface{}, path types.FilePath, triggerSource string) {
	// Don't send analytics if old and new values are the same
	if oldValue == newValue {
		return
	}

	// Don't send analytics if both values are empty
	if isEmptyValue(oldValue) && isEmptyValue(newValue) {
		return
	}

	event := NewAnalyticsEventParam("Config changed", nil, path)

	// Ensure empty strings are always included in the extension
	// Some analytics frameworks filter out empty strings, so we need to ensure they're preserved
	extension := make(map[string]any)
	extension["config::"+field+"::oldValue"] = oldValue
	extension["config::"+field+"::newValue"] = newValue
	extension["config::"+field+"::triggerSource"] = triggerSource

	event.Extension = extension
	SendAnalytics(c.Engine(), c.DeviceID(), event, nil)
}

// SendCollectionChangeAnalyticsGlobal sends analytics for collection changes to all workspace folders
func SendCollectionChangeAnalyticsGlobal[T cmp.Ordered](c *config.Config, field string, oldValue, newValue []T, triggerSource string, addedSuffix, removedSuffix, countSuffix string) {
	sendCollectionChangeAnalyticsInternal(c, field, oldValue, newValue, triggerSource, addedSuffix, removedSuffix, countSuffix, true, types.FilePath(""))
}

// SendCollectionChangeAnalytics sends analytics for collection changes
func SendCollectionChangeAnalytics[T cmp.Ordered](c *config.Config, field string, oldValue, newValue []T, path types.FilePath, triggerSource string, addedSuffix, removedSuffix, countSuffix string) {
	sendCollectionChangeAnalyticsInternal(c, field, oldValue, newValue, triggerSource, addedSuffix, removedSuffix, countSuffix, false, path)
}

// sendCollectionChangeAnalyticsInternal contains the common logic for collection change analytics
func sendCollectionChangeAnalyticsInternal[T cmp.Ordered](c *config.Config, field string, oldValue, newValue []T, triggerSource string, addedSuffix, removedSuffix, countSuffix string, isGlobal bool, path types.FilePath) {
	// Don't send analytics if collections are identical
	if util.SlicesEqualIgnoringOrder(oldValue, newValue) {
		return
	}

	// Create maps for easier lookup
	oldMap := make(map[T]bool)
	for _, item := range oldValue {
		oldMap[item] = true
	}

	newMap := make(map[T]bool)
	for _, item := range newValue {
		newMap[item] = true
	}

	// Find added items
	for _, item := range newValue {
		if !oldMap[item] {
			// Don't send analytics for empty values, where old value is ""
			if !isEmptyValue(item) {
				if isGlobal {
					SendConfigChangedAnalytics(c, field+addedSuffix, "", item, triggerSource)
				} else {
					SendConfigChangedAnalyticsEvent(c, field+addedSuffix, "", item, path, triggerSource)
				}
			}
		}
	}

	// Find removed items
	for _, item := range oldValue {
		if !newMap[item] {
			// Don't send analytics for removing empty values, when new value is ""
			if !isEmptyValue(item) {
				if isGlobal {
					SendConfigChangedAnalytics(c, field+removedSuffix, item, "", triggerSource)
				} else {
					SendConfigChangedAnalyticsEvent(c, field+removedSuffix, item, "", path, triggerSource)
				}
			}
		}
	}

	// Send count change analytics
	oldCount := len(oldValue)
	newCount := len(newValue)
	if oldCount != newCount {
		if isGlobal {
			SendConfigChangedAnalytics(c, field+countSuffix, oldCount, newCount, triggerSource)
		} else {
			SendConfigChangedAnalyticsEvent(c, field+countSuffix, oldCount, newCount, path, triggerSource)
		}
	}
}

// SendMapConfigChangedAnalytics sends analytics for map fields
func SendMapConfigChangedAnalytics[K comparable, V any](c *config.Config, field string, oldValue, newValue map[K]V, path types.FilePath, triggerSource string) {
	// Create maps for easier lookup
	oldMap := make(map[K]V)
	for k, v := range oldValue {
		oldMap[k] = v
	}

	newMap := make(map[K]V)
	for k, v := range newValue {
		newMap[k] = v
	}

	// Find added/modified keys
	for k, newV := range newValue {
		if oldV, exists := oldMap[k]; !exists {
			// Key was added
			SendConfigChangedAnalytics(c, field+"KeyAdded", "", k, triggerSource)
		} else if !reflect.DeepEqual(oldV, newV) {
			// Key was modified
			SendConfigChangedAnalytics(c, field+"KeyModified", oldV, newV, triggerSource)
		}
	}

	// Find removed keys
	for k := range oldValue {
		if _, exists := newMap[k]; !exists {
			// Key was removed
			SendConfigChangedAnalytics(c, field+"KeyRemoved", k, "", triggerSource)
		}
	}

	// Send count change analytics
	oldCount := len(oldValue)
	newCount := len(newValue)
	if oldCount != newCount {
		SendConfigChangedAnalytics(c, field+"Count", oldCount, newCount, triggerSource)
	}
}

// SendAnalyticsForFields sends analytics for struct fields
func SendAnalyticsForFields[T any](c *config.Config, prefix string, oldValue, newValue *T, triggerSource string, fieldMappings map[string]func(*T) any) {
	for fieldName, getter := range fieldMappings {
		oldVal := getter(oldValue)
		newVal := getter(newValue)
		if oldVal != newVal {
			SendConfigChangedAnalytics(c, prefix+fieldName, oldVal, newVal, triggerSource)
		}
	}
}

// isEmptyValue checks if a value is considered empty
func isEmptyValue(value any) bool {
	if value == nil {
		return true
	}

	switch v := value.(type) {
	case string:
		return v == ""
	case []string:
		return len(v) == 0
	case []int:
		return len(v) == 0
	case []float64:
		return len(v) == 0
	case []bool:
		return len(v) == 0
	case map[string]string:
		return len(v) == 0
	case map[string]int:
		return len(v) == 0
	case map[string]any:
		return len(v) == 0
	default:
		// For other types, use reflection to check if it's the zero value
		// This handles slices, maps, and other types generically
		rv := reflect.ValueOf(value)
		switch rv.Kind() {
		case reflect.Slice, reflect.Map, reflect.Array:
			return rv.Len() == 0
		case reflect.Ptr, reflect.Interface:
			return rv.IsNil()
		default:
			return reflect.DeepEqual(value, reflect.Zero(reflect.TypeOf(value)).Interface())
		}
	}
}
