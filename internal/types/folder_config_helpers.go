/*
 * © 2022-2026 Snyk Limited
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

package types

import (
	"github.com/snyk/code-client-go/pkg/code/sast_contract"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/internal/product"
)

// FolderConfigSnapshot holds folder config values read from configuration for comparison and analytics.
// Used when struct fields have been removed and all values live in configuration prefix keys.
type FolderConfigSnapshot struct {
	BaseBranch           string
	LocalBranches        []string
	AdditionalParameters []string
	AdditionalEnv        string
	ReferenceFolderPath  FilePath
	ScanCommandConfig    map[product.Product]ScanCommandConfig
	PreferredOrg         string
	AutoDeterminedOrg    string
	OrgSetByUser         bool
	UserOverrides        map[string]any
}

// coerceToLocalConfigField handles both in-memory *LocalConfigField (during session)
// and map[string]interface{} (after JSON deserialization on restart).
func coerceToLocalConfigField(val any) (*configresolver.LocalConfigField, bool) {
	if lf, ok := val.(*configresolver.LocalConfigField); ok {
		return lf, lf != nil && lf.Changed
	}
	m, ok := val.(map[string]interface{})
	if !ok {
		return nil, false
	}
	changed, _ := m["changed"].(bool)
	if !changed {
		return nil, false
	}
	return &configresolver.LocalConfigField{Value: m["value"], Changed: true}, true
}

func getUserFolderValue(conf configuration.Configuration, fp string, name string) (any, bool) {
	key := configresolver.UserFolderKey(fp, name)
	val := conf.Get(key)
	if val == nil {
		return nil, false
	}
	lf, ok := coerceToLocalConfigField(val)
	if !ok {
		return nil, false
	}
	return lf.Value, true
}

func getUserString(conf configuration.Configuration, fp, name string) string {
	if v, ok := getUserFolderValue(conf, fp, name); ok {
		if str, ok := v.(string); ok {
			return str
		}
	}
	return ""
}

func getUserBool(conf configuration.Configuration, fp, name string) bool {
	if v, ok := getUserFolderValue(conf, fp, name); ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func getMetaString(conf configuration.Configuration, fp, name string) string {
	if v := conf.Get(configresolver.FolderMetadataKey(fp, name)); v != nil {
		if str, ok := v.(string); ok {
			return str
		}
	}
	return ""
}

// ReadFolderConfigSnapshot reads folder config values from configuration into a snapshot.
// An optional ConfigurationOptionsMetaData may be passed to populate UserOverrides for org-scoped flags.
func ReadFolderConfigSnapshot(conf configuration.Configuration, folderPath FilePath, fms ...workflow.ConfigurationOptionsMetaData) FolderConfigSnapshot {
	s := FolderConfigSnapshot{UserOverrides: make(map[string]any)}
	if conf == nil {
		return s
	}
	fp := string(PathKey(folderPath))
	if fp == "" {
		return s
	}

	s.BaseBranch = getUserString(conf, fp, SettingBaseBranch)
	s.AdditionalEnv = getUserString(conf, fp, SettingAdditionalEnvironment)
	s.ReferenceFolderPath = FilePath(getUserString(conf, fp, SettingReferenceFolder))
	s.PreferredOrg = getUserString(conf, fp, SettingPreferredOrg)
	s.OrgSetByUser = getUserBool(conf, fp, SettingOrgSetByUser)
	s.AutoDeterminedOrg = getMetaString(conf, fp, SettingAutoDeterminedOrg)

	if v := conf.Get(configresolver.FolderMetadataKey(fp, SettingLocalBranches)); v != nil {
		switch typed := v.(type) {
		case []string:
			s.LocalBranches = typed
		case []interface{}:
			strs := make([]string, 0, len(typed))
			for _, item := range typed {
				if str, ok := item.(string); ok {
					strs = append(strs, str)
				}
			}
			s.LocalBranches = strs
		}
	}
	if v, ok := getUserFolderValue(conf, fp, SettingAdditionalParameters); ok {
		switch typed := v.(type) {
		case []string:
			s.AdditionalParameters = typed
		case []interface{}:
			// After JSON round-trip, []string is deserialized as []interface{}
			strs := make([]string, 0, len(typed))
			for _, item := range typed {
				if str, ok := item.(string); ok {
					strs = append(strs, str)
				}
			}
			s.AdditionalParameters = strs
		}
	}
	if v, ok := getUserFolderValue(conf, fp, SettingScanCommandConfig); ok {
		if m, ok := v.(map[product.Product]ScanCommandConfig); ok {
			s.ScanCommandConfig = m
		}
	}

	var fm workflow.ConfigurationOptionsMetaData
	if len(fms) > 0 {
		fm = fms[0]
	}
	if fm != nil {
		for _, name := range fm.ConfigurationOptionsByAnnotation(configresolver.AnnotationScope, string(configresolver.FolderScope)) {
			if v, ok := getUserFolderValue(conf, fp, name); ok {
				s.UserOverrides[name] = v
			}
		}
	}
	return s
}

// HasUserOverride returns true if the setting has a user override in configuration.
func HasUserOverride(conf configuration.Configuration, folderPath FilePath, settingName string) bool {
	if conf == nil {
		return false
	}
	key := configresolver.UserFolderKey(string(PathKey(folderPath)), settingName)
	val := conf.Get(key)
	if val == nil {
		return false
	}
	_, ok := coerceToLocalConfigField(val)
	return ok
}

// SetAutoDeterminedOrg writes the auto-determined org to configuration.
func SetAutoDeterminedOrg(conf configuration.Configuration, folderPath FilePath, value string) {
	SetFolderMetadataSetting(conf, folderPath, SettingAutoDeterminedOrg, value)
}

// SetPreferredOrgAndOrgSetByUser writes PreferredOrg and OrgSetByUser to configuration.
func SetPreferredOrgAndOrgSetByUser(conf configuration.Configuration, folderPath FilePath, preferredOrg string, orgSetByUser bool) {
	SetFolderUserSetting(conf, folderPath, SettingPreferredOrg, preferredOrg)
	SetFolderUserSetting(conf, folderPath, SettingOrgSetByUser, orgSetByUser)
}

// CopyFolderConfigValues copies all prefix key values from one folder path to another.
// Used when creating a temporary folder config (e.g. for base branch scans) that should
// inherit all settings from the original workspace folder.
func CopyFolderConfigValues(conf configuration.Configuration, srcPath, dstPath FilePath) {
	if conf == nil {
		return
	}
	src := string(PathKey(srcPath))
	dst := string(PathKey(dstPath))
	if src == "" || dst == "" || src == dst {
		return
	}

	userSettings := []string{
		SettingBaseBranch, SettingReferenceBranch, SettingAdditionalParameters,
		SettingAdditionalEnvironment, SettingReferenceFolder, SettingScanCommandConfig,
		SettingPreferredOrg, SettingOrgSetByUser,
	}
	for _, name := range userSettings {
		if v := conf.Get(configresolver.UserFolderKey(src, name)); v != nil {
			key := configresolver.UserFolderKey(dst, name)
			conf.PersistInStorage(key)
			conf.Set(key, v)
		}
	}

	metaSettings := []string{SettingAutoDeterminedOrg, SettingLocalBranches, SettingSastSettings}
	for _, name := range metaSettings {
		if v := conf.Get(configresolver.FolderMetadataKey(src, name)); v != nil {
			key := configresolver.FolderMetadataKey(dst, name)
			conf.PersistInStorage(key)
			conf.Set(key, v)
		}
	}
}

// GetSastSettings reads the SAST settings from configuration for a folder.
func GetSastSettings(conf configuration.Configuration, folderPath FilePath) *sast_contract.SastResponse {
	if conf == nil {
		return nil
	}
	key := configresolver.FolderMetadataKey(string(PathKey(folderPath)), SettingSastSettings)
	val := conf.Get(key)
	if val == nil {
		return nil
	}
	if settings, ok := val.(*sast_contract.SastResponse); ok {
		return settings
	}
	return nil
}

// SetSastSettings writes the SAST settings to configuration for a folder.
func SetSastSettings(conf configuration.Configuration, folderPath FilePath, settings *sast_contract.SastResponse) {
	if conf == nil || settings == nil {
		return
	}
	SetFolderMetadataSetting(conf, folderPath, SettingSastSettings, settings)
}

// SetFolderUserSetting writes a user folder setting and marks it for persistence.
func SetFolderUserSetting(conf configuration.Configuration, folderPath FilePath, name string, value any) {
	if conf == nil {
		return
	}
	key := configresolver.UserFolderKey(string(PathKey(folderPath)), name)
	conf.PersistInStorage(key)
	conf.Set(key, &configresolver.LocalConfigField{Value: value, Changed: true})
}

// SetFolderMetadataSetting writes a folder metadata setting and marks it for persistence.
func SetFolderMetadataSetting(conf configuration.Configuration, folderPath FilePath, name string, value any) {
	if conf == nil {
		return
	}
	key := configresolver.FolderMetadataKey(string(PathKey(folderPath)), name)
	conf.PersistInStorage(key)
	conf.Set(key, value)
}
