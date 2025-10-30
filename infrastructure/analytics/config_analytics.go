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
	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

// TriggerSource represents the source of a configuration change for analytics purposes
type TriggerSource string

const (
	// TriggerSourceInitialize indicates settings are being initialized (first load, LSP init)
	TriggerSourceInitialize TriggerSource = "initialize"

	// TriggerSourceIDE indicates settings were changed by the IDE or user
	TriggerSourceIDE TriggerSource = "ide"

	// TriggerSourceTest indicates the change is from a test scenario
	TriggerSourceTest TriggerSource = "test"
)

// String returns the string representation of the trigger source
func (a TriggerSource) String() string {
	return string(a)
}

// SendConfigChangedAnalytics sends analytics for primitive value global config changes
func SendConfigChangedAnalytics(c *config.Config, configName string, oldVal any, newVal any, triggerSource TriggerSource) {
	// Don't send analytics if old and new values are identical
	if util.AreValuesEqual(oldVal, newVal) {
		return
	}

	// Send to first folder's org only, since global config changes are not folder-specific, but analytics have to be sent
	// to a specific org, so the first folder's org has as good a chance as any to work and not 404.
	// TODO - This is a temporary solution to avoid inflating analytics counts.
	ws := c.Workspace()
	if ws != nil {
		folders := ws.Folders()
		if len(folders) > 0 {
			go SendConfigChangedAnalyticsEvent(c, configName, oldVal, newVal, folders[0].Path(), triggerSource)
			return
		}
	}

	// Fallback: If no workspace or no folders, send with empty path (empty org triggers GAF fallback to user's preferred org from the web UI)
	go SendConfigChangedAnalyticsEvent(c, configName, oldVal, newVal, "", triggerSource)
}

// SendConfigChangedAnalyticsEvent sends a single analytics event for a primitive value config change for a given folder path
func SendConfigChangedAnalyticsEvent(c *config.Config, field string, oldValue, newValue any, path types.FilePath, triggerSource TriggerSource) {
	// Don't send analytics if old and new values are the same
	if util.AreValuesEqual(oldValue, newValue) {
		return
	}

	// Don't send analytics if both values are empty
	if util.IsEmptyValue(oldValue) && util.IsEmptyValue(newValue) {
		return
	}

	event := NewAnalyticsEventParam("Config changed", nil, path)

	// Ensure empty strings are always included in the extension
	// Some analytics frameworks filter out empty strings, so we need to ensure they're preserved
	extension := make(map[string]any)
	extension["config::"+field+"::oldValue"] = oldValue
	extension["config::"+field+"::newValue"] = newValue
	extension["config::"+field+"::triggerSource"] = triggerSource.String()

	event.Extension = extension
	folderOrg := c.FolderOrganization(path)
	SendAnalytics(c.Engine(), c.DeviceID(), folderOrg, event, nil)
}

// SendAnalyticsForFields sends analytics for struct fields
func SendAnalyticsForFields[T any](c *config.Config, prefix string, oldValue, newValue *T, triggerSource TriggerSource, fieldMappings map[string]func(*T) any) {
	for fieldName, getter := range fieldMappings {
		oldVal := getter(oldValue)
		newVal := getter(newValue)
		if !util.AreValuesEqual(oldVal, newVal) {
			SendConfigChangedAnalytics(c, prefix+fieldName, oldVal, newVal, triggerSource)
		}
	}
}
