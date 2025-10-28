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

package featureflag

import (
	"fmt"
	"sync"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow"
	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow/sast_contract"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/local_workflows/ignore_workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
)

const (
	SnykCodeConsistentIgnores string = "snykCodeConsistentIgnores"
	SnykCodeInlineIgnore      string = "snykCodeInlineIgnore"
	IgnoreApprovalEnabled     string = "internal_iaw_enabled"
)

var Flags = []string{
	SnykCodeConsistentIgnores,
	SnykCodeInlineIgnore,
	IgnoreApprovalEnabled,
}

type Service interface {
	GetFromFolderConfig(folderPath types.FilePath, flag string) bool
	GetSastSettingsFromFolderConfig(folderPath types.FilePath) *sast_contract.SastResponse
	PopulateFolderConfig(folderConfig *types.FolderConfig)
	FlushCache()
}

type serviceImpl struct {
	c                 *config.Config
	orgToFlag         map[string]map[string]bool
	orgToSastSettings map[string]*sast_contract.SastResponse
	mutex             *sync.Mutex
}

func New(c *config.Config) Service {
	return &serviceImpl{
		c:                 c,
		orgToFlag:         make(map[string]map[string]bool),
		orgToSastSettings: make(map[string]*sast_contract.SastResponse),
		mutex:             &sync.Mutex{},
	}
}

func (s *serviceImpl) fetch(org string) map[string]bool {
	s.mutex.Lock()
	cached := s.orgToFlag[org]
	if cached != nil {
		s.mutex.Unlock()
		return cached
	}

	s.orgToFlag[org] = make(map[string]bool)
	s.mutex.Unlock()

	var wg sync.WaitGroup
	wg.Add(len(Flags))

	for _, flag := range Flags {
		go func() {
			defer wg.Done()

			conf := s.c.Engine().GetConfiguration().Clone()
			conf.Set(configuration.ORGANIZATION, org)

			var enabled bool
			var err error

			// IgnoreApprovalEnabled is fetched differently from other feature flags
			if flag == IgnoreApprovalEnabled {
				enabled, err = conf.GetBoolWithError(ignore_workflow.ConfigIgnoreApprovalEnabled)
			} else {
				enabled, err = config_utils.GetFeatureFlagValue(flag, conf, s.c.Engine().GetNetworkAccess().GetHttpClient())
			}

			if err != nil {
				// TODO: wait until @startOfflineDetection is integrated. If error isn't related to network issues, there is nothing user can do anyway
				s.c.Logger().Err(err).Str("method", "GetFlags").Msgf("couldn't get config value %s", flag)
			}

			s.mutex.Lock()
			s.orgToFlag[org][flag] = enabled
			s.mutex.Unlock()
		}()
	}

	wg.Wait()

	s.mutex.Lock()
	result := s.orgToFlag[org]
	s.mutex.Unlock()

	return result
}

func (s *serviceImpl) fetchSastSettings(org string) (*sast_contract.SastResponse, error) {
	s.mutex.Lock()
	cached := s.orgToSastSettings[org]
	if cached != nil {
		s.mutex.Unlock()
		return cached, nil
	}
	s.mutex.Unlock()

	gafConfig := s.c.Engine().GetConfiguration().Clone()
	gafConfig.Set(configuration.ORGANIZATION, org)

	response, err := gafConfig.GetWithError(code_workflow.ConfigurationSastSettings)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch SAST settings for org %s: %w", org, err)
	}

	sastResponse, ok := response.(*sast_contract.SastResponse)
	if !ok {
		return nil, fmt.Errorf("failed to type assert SAST response for org %s", org)
	}

	s.mutex.Lock()
	s.orgToSastSettings[org] = sastResponse
	s.mutex.Unlock()

	return sastResponse, nil
}

func (s *serviceImpl) FlushCache() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.orgToFlag = make(map[string]map[string]bool)
	s.orgToSastSettings = make(map[string]*sast_contract.SastResponse)
}

func (s *serviceImpl) GetFromFolderConfig(folderPath types.FilePath, flag string) bool {
	folderConfig := s.c.FolderConfig(folderPath)
	v, ok := folderConfig.FeatureFlags[flag]
	if !ok {
		s.c.Logger().Warn().Str("method", "GetFromFolderConfig").Msgf("feature flag %s not found in folder config for path %s", flag, folderPath)
		return false
	}

	return v
}

func (s *serviceImpl) GetSastSettingsFromFolderConfig(folderPath types.FilePath) *sast_contract.SastResponse {
	folderConfig := s.c.FolderConfig(folderPath)
	if folderConfig.SastSettings == nil {
		// Return default struct - error already logged during population
		return &sast_contract.SastResponse{}
	}
	return folderConfig.SastSettings
}

func (s *serviceImpl) PopulateFolderConfig(folderConfig *types.FolderConfig) {
	org := s.c.FolderOrganization(folderConfig.FolderPath)

	// Fetch feature flags and SAST settings in parallel
	var flags map[string]bool
	var sastSettings *sast_contract.SastResponse
	var sastErr error

	var wg sync.WaitGroup
	wg.Add(2)

	// Fetch feature flags
	go func() {
		defer wg.Done()
		flags = s.fetch(org)
	}()

	// Fetch SAST settings
	go func() {
		defer wg.Done()
		sastSettings, sastErr = s.fetchSastSettings(org)
	}()

	wg.Wait()

	// Populate folder config
	folderConfig.FeatureFlags = flags

	if sastErr != nil {
		s.c.Logger().Err(sastErr).Str("method", "PopulateFolderConfig").Msgf("couldn't get SAST settings for org %s", org)
	} else {
		folderConfig.SastSettings = sastSettings
	}
}
