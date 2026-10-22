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
	"strings"

	"github.com/snyk/code-client-go/pkg/code/sast_contract"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/internal/util"

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

func getUserFolderValue(conf configuration.Configuration, fp string, name string) (any, bool) {
	key := configresolver.UserFolderKey(fp, name)
	val := conf.Get(key)
	if val == nil {
		return nil, false
	}
	lf, ok := util.CoerceToLocalConfigField(val)
	if lf == nil || !ok {
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
	s.LocalBranches = getStoredStringSlice(conf, configresolver.FolderMetadataKey(fp, SettingLocalBranches))
	s.AdditionalParameters = getStringSliceFromUserConfig(conf, fp, SettingAdditionalParameters)
	readScanCommandConfig(conf, fp, &s)
	readUserOverrides(conf, fp, fms, &s)
	return s
}

func readScanCommandConfig(conf configuration.Configuration, fp string, s *FolderConfigSnapshot) {
	if v, ok := getUserFolderValue(conf, fp, SettingScanCommandConfig); ok {
		if m, ok := v.(map[product.Product]ScanCommandConfig); ok {
			s.ScanCommandConfig = m
		}
	}
}

func readUserOverrides(conf configuration.Configuration, fp string, fms []workflow.ConfigurationOptionsMetaData, s *FolderConfigSnapshot) {
	var fm workflow.ConfigurationOptionsMetaData
	if len(fms) > 0 {
		fm = fms[0]
	}
	if fm == nil {
		return
	}
	for _, name := range fm.ConfigurationOptionsByAnnotation(configresolver.AnnotationScope, string(configresolver.FolderScope)) {
		if v, ok := getUserFolderValue(conf, fp, name); ok {
			s.UserOverrides[name] = v
		}
	}
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
	_, ok := util.CoerceToLocalConfigField(val)
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

// CopyFolderConfigValues copies every value stored under srcPath to dstPath: user folder settings,
// folder metadata (including feature flags) and LDX-Sync org-folder settings. The copies stay in memory.
func CopyFolderConfigValues(conf configuration.Configuration, srcPath, dstPath FilePath) {
	if conf == nil {
		return
	}
	src := string(PathKey(srcPath))
	dst := string(PathKey(dstPath))
	if src == "" || dst == "" || src == dst {
		return
	}
	for _, key := range folderConfigKeys(conf, src) {
		if v := conf.Get(key.at(src)); v != nil {
			conf.Set(key.at(dst), v)
		}
	}
}

// ClearFolderConfigValues sets every value stored under folderPath to nil without touching storage.
// GAF has no in-memory delete, so AllKeys keeps listing the cleared names.
func ClearFolderConfigValues(conf configuration.Configuration, folderPath FilePath) {
	if conf == nil {
		return
	}
	fp := string(PathKey(folderPath))
	if fp == "" {
		return
	}
	for _, key := range folderConfigKeys(conf, fp) {
		conf.Set(key.at(fp), nil)
	}
}

type folderConfigKey struct {
	family, name string
}

func (k folderConfigKey) at(folderPath string) string {
	return k.family + folderPath + ":" + k.name
}

// AllKeys returns keys lowercased and flattens map values (e.g. a LocalConfigField reloaded from storage)
// into "<name>.<field>" leaves, so matching is case-insensitive and each setting is cut at its first dot.
func folderConfigKeys(conf configuration.Configuration, folderPath string) []folderConfigKey {
	fp := strings.ToLower(folderPath) + ":"
	seen := map[folderConfigKey]bool{}
	var keys []folderConfigKey
	for _, key := range conf.AllKeys() {
		family, rest, ok := cutFolderFamily(key)
		if !ok {
			continue
		}
		after, ok := strings.CutPrefix(rest, fp)
		if !ok {
			continue
		}
		name, _, _ := strings.Cut(after, ".")
		if name == "" || strings.Contains(name, ":") {
			continue
		}
		k := folderConfigKey{family: family, name: name}
		if seen[k] {
			continue
		}
		seen[k] = true
		keys = append(keys, k)
	}
	return keys
}

func cutFolderFamily(key string) (family, rest string, ok bool) {
	userFolder := configresolver.PrefixUser + ":" + configresolver.PrefixFolder + ":"
	if rest, ok = strings.CutPrefix(key, userFolder); ok {
		return userFolder, rest, true
	}
	folder := configresolver.PrefixFolder + ":"
	if rest, ok = strings.CutPrefix(key, folder); ok {
		return folder, rest, true
	}
	remote := configresolver.PrefixRemote + ":"
	afterRemote, ok := strings.CutPrefix(key, remote)
	if !ok {
		return "", "", false
	}
	org, afterOrg, ok := strings.Cut(afterRemote, ":")
	if !ok {
		return "", "", false
	}
	remoteFolder := configresolver.PrefixFolder + ":"
	if rest, ok = strings.CutPrefix(afterOrg, remoteFolder); ok {
		return remote + org + ":" + remoteFolder, rest, true
	}
	return "", "", false
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
