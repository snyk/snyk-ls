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

// Package analytics implements analytics functionality
package analytics

import (
	"reflect"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

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
func SendConfigChangedAnalytics(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, configName string, oldVal any, newVal any, triggerSource TriggerSource, configResolver types.ConfigResolverInterface) {
	// Don't send analytics if old and new values are identical
	if util.AreValuesEqual(oldVal, newVal) {
		return
	}

	// Send to any folder's org, since global config changes are not folder-specific, but analytics have to be sent
	// to a specific org, so any folder's org has as good a chance as any other to work and not 404.
	// TODO - This is a temporary solution to avoid inflating analytics counts.
	ws := config.GetWorkspace(conf)
	if ws != nil {
		folders := ws.Folders()
		if len(folders) > 0 {
			go SendConfigChangedAnalyticsEvent(conf, engine, logger, configName, oldVal, newVal, folders[0].Path(), triggerSource, configResolver)
			return
		}
	}

	// Fallback: If no workspace or no folders, send with empty path (will use global org as a fallback)
	go SendConfigChangedAnalyticsEvent(conf, engine, logger, configName, oldVal, newVal, "", triggerSource, configResolver)
}

// SendConfigChangedAnalyticsEvent sends a single analytics event for a primitive value config change for a given folder path
func SendConfigChangedAnalyticsEvent(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, field string, oldValue, newValue any, path types.FilePath, triggerSource TriggerSource, configResolver types.ConfigResolverInterface) {
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

	// If path is empty (no folder context), use global org directly as a fallback,
	// this is fine since these analytics are not exposed in customer TopCoat reports, and are only consumed by us.
	var folderOrg string
	if path == "" {
		folderOrg = types.GetGlobalOrganization(conf)
	} else {
		folderOrg = config.FolderOrganization(conf, path, logger)
	}

	deviceId := ""
	if configResolver != nil {
		deviceId = configResolver.GetString(types.SettingDeviceId, nil)
	}
	SendAnalytics(engine, deviceId, folderOrg, event, nil)
}

// SendAnalyticsForStructFields sends analytics for each exported struct field that changed
// between oldValue and newValue, using reflection to iterate the fields.
func SendAnalyticsForStructFields(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, prefix string, oldValue, newValue any, triggerSource TriggerSource, configResolver types.ConfigResolverInterface) {
	oldV := reflect.ValueOf(oldValue)
	newV := reflect.ValueOf(newValue)
	if oldV.Kind() == reflect.Ptr {
		oldV = oldV.Elem()
	}
	if newV.Kind() == reflect.Ptr {
		newV = newV.Elem()
	}
	t := oldV.Type()
	for i := range t.NumField() {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}
		oldVal := oldV.Field(i).Interface()
		newVal := newV.Field(i).Interface()
		if !util.AreValuesEqual(oldVal, newVal) {
			SendConfigChangedAnalytics(conf, engine, logger, prefix+field.Name, oldVal, newVal, triggerSource, configResolver)
		}
	}
}
