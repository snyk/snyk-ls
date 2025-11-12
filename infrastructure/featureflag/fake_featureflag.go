/*
 * © 2025 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http.www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package featureflag implements remote feature flag support
package featureflag

import (
	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow/sast_contract"

	"github.com/snyk/snyk-ls/internal/types"
)

type FakeFeatureFlagService struct {
	Flags            map[string]bool
	FlushCacheCalled bool
	SastSettings     *sast_contract.SastResponse
}

func NewFakeService() *FakeFeatureFlagService {
	return &FakeFeatureFlagService{Flags: make(map[string]bool)}
}

func (f *FakeFeatureFlagService) GetFromFolderConfig(folderPath types.FilePath, flag string) bool {
	val, ok := f.Flags[flag]
	if !ok {
		return false
	}
	return val
}

func (f *FakeFeatureFlagService) GetSastSettingsFromFolderConfig(folderPath types.FilePath) *sast_contract.SastResponse {
	return f.SastSettings
}

func (f *FakeFeatureFlagService) PopulateFolderConfig(folderConfig *types.FolderConfig) {
	folderConfig.FeatureFlags = f.Flags
	folderConfig.SastSettings = f.SastSettings
}

func (f *FakeFeatureFlagService) FlushCache() {
	f.FlushCacheCalled = true
}
