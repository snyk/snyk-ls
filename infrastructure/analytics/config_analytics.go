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
	"reflect"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
)

// Sender defines the interface for sending analytics events
type Sender interface {
	SendAnalytics(field string, oldVal, newVal any, triggerSource string)
}

// ConfigAnalyticsSender defines the interface for sending config-specific analytics events
type ConfigAnalyticsSender interface {
	SendConfigChangedAnalytics(c *config.Config, configName string, oldVal, newVal any, triggerSource string)
}

// DefaultConfigAnalyticsSender implements ConfigAnalyticsSender using the real analytics infrastructure
type DefaultConfigAnalyticsSender struct{}

func (d *DefaultConfigAnalyticsSender) SendConfigChangedAnalytics(c *config.Config, configName string, oldVal, newVal any, triggerSource string) {
	SendConfigChangedAnalytics(c, configName, oldVal, newVal, triggerSource)
}

// SendConfigChangedAnalytics sends analytics for primitive values only
func SendConfigChangedAnalytics(c *config.Config, configName string, oldVal any, newVal any, triggerSource string) {
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
	event := NewAnalyticsEventParam("Config changed", nil, path)

	event.Extension = map[string]any{
		"config::" + field + "::oldValue":      oldValue,
		"config::" + field + "::newValue":      newValue,
		"config::" + field + "::triggerSource": triggerSource,
	}
	SendAnalytics(c.Engine(), c.DeviceID(), event, nil)
}

// SendCollectionChangeAnalytics sends analytics for collection changes
func SendCollectionChangeAnalytics[T comparable](c *config.Config, field string, oldValue, newValue []T, triggerSource string, addedSuffix, removedSuffix, countSuffix string) {
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
			SendConfigChangedAnalytics(c, field+addedSuffix, "", item, triggerSource)
		}
	}

	// Find removed items
	for _, item := range oldValue {
		if !newMap[item] {
			SendConfigChangedAnalytics(c, field+removedSuffix, item, "", triggerSource)
		}
	}

	// Send count change analytics
	oldCount := len(oldValue)
	newCount := len(newValue)
	if oldCount != newCount {
		SendConfigChangedAnalytics(c, field+countSuffix, oldCount, newCount, triggerSource)
	}
}

// SendCollectionChangeAnalyticsWithSender sends analytics for collection changes using a custom sender
func SendCollectionChangeAnalyticsWithSender[T comparable](c *config.Config, field string, oldValue, newValue []T, triggerSource string, addedSuffix, removedSuffix, countSuffix string, sender ConfigAnalyticsSender) {
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
			sender.SendConfigChangedAnalytics(c, field+addedSuffix, "", item, triggerSource)
		}
	}

	// Find removed items
	for _, item := range oldValue {
		if !newMap[item] {
			sender.SendConfigChangedAnalytics(c, field+removedSuffix, item, "", triggerSource)
		}
	}

	// Send count change analytics
	oldCount := len(oldValue)
	newCount := len(newValue)
	if oldCount != newCount {
		sender.SendConfigChangedAnalytics(c, field+countSuffix, oldCount, newCount, triggerSource)
	}
}

// SendTrustedFoldersAnalytics sends analytics for individual trusted folder changes
func SendTrustedFoldersAnalytics(c *config.Config, oldFolders, newFolders []types.FilePath, triggerSource string) {
	// Note: Path normalization should be handled at the folder trust level, not here
	// The trusted folders should already be normalized when they are stored/retrieved
	SendCollectionChangeAnalytics(c, "trustedFolder", oldFolders, newFolders, triggerSource, "Added", "Removed", "Count")
}

// SendMapConfigChangedAnalytics sends analytics for map fields
func SendMapConfigChangedAnalytics[K comparable, V any](c *config.Config, field string, oldValue, newValue map[K]V, path types.FilePath, triggerSource string) {
	SendMapConfigChangedAnalyticsWithSender(c, field, oldValue, newValue, path, triggerSource, &DefaultConfigAnalyticsSender{})
}

// SendMapConfigChangedAnalyticsWithSender sends analytics for map fields using a custom sender
func SendMapConfigChangedAnalyticsWithSender[K comparable, V any](c *config.Config, field string, oldValue, newValue map[K]V, path types.FilePath, triggerSource string, sender ConfigAnalyticsSender) {
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
			sender.SendConfigChangedAnalytics(c, field+"KeyAdded", "", k, triggerSource)
		} else if !reflect.DeepEqual(oldV, newV) {
			// Key was modified
			sender.SendConfigChangedAnalytics(c, field+"KeyModified", oldV, newV, triggerSource)
		}
	}

	// Find removed keys
	for k := range oldValue {
		if _, exists := newMap[k]; !exists {
			// Key was removed
			sender.SendConfigChangedAnalytics(c, field+"KeyRemoved", k, "", triggerSource)
		}
	}

	// Send count change analytics
	oldCount := len(oldValue)
	newCount := len(newValue)
	if oldCount != newCount {
		sender.SendConfigChangedAnalytics(c, field+"Count", oldCount, newCount, triggerSource)
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
