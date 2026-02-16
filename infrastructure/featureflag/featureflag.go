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
	"maps"
	"sync"
	"time"

	"github.com/erni27/imcache"
	"github.com/snyk/code-client-go/pkg/code"
	"github.com/snyk/code-client-go/pkg/code/sast_contract"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/local_workflows/ignore_workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/types"
)

const (
	SnykCodeConsistentIgnores     string = "snykCodeConsistentIgnores"
	SnykCodeInlineIgnore          string = "snykCodeInlineIgnore"
	IgnoreApprovalEnabled         string = "internal_iaw_enabled"
	UseExperimentalRiskScoreInCLI string = "useExperimentalRiskScoreInCLI"
	UseExperimentalRiskScore      string = "useExperimentalRiskScore"
	UseOsTest                     string = "useTestShimForOSCliTest"
)

var Flags = []string{
	SnykCodeConsistentIgnores,
	SnykCodeInlineIgnore,
	IgnoreApprovalEnabled,
	UseExperimentalRiskScoreInCLI,
	UseExperimentalRiskScore,
	UseOsTest,
}

func UseOsTestWorkflow(folderConfig types.ImmutableFolderConfig) bool {
	return folderConfig.GetFeatureFlag(UseExperimentalRiskScoreInCLI) || folderConfig.GetFeatureFlag(UseOsTest)
}

// ExternalCallsProvider abstracts configuration and API calls for testability
type ExternalCallsProvider interface {
	getIgnoreApprovalEnabled(org string) (bool, error)
	getFeatureFlag(flag string, org string) (bool, error)
	getSastSettings(org string) (*sast_contract.SastResponse, error)
	folderOrganization(path types.FilePath) string
}

type Service interface {
	GetFromStoredFolderConfig(folderPath types.FilePath, flag string) bool
	PopulateFolderConfig(folderConfig *types.FolderConfig)
	FlushCache()
}

type externalCallsProvider struct {
	c *config.Config
}

func (p *externalCallsProvider) getIgnoreApprovalEnabled(org string) (bool, error) {
	conf := p.c.Engine().GetConfiguration().Clone()
	conf.Set(configuration.ORGANIZATION, org)
	return conf.GetBoolWithError(ignore_workflow.ConfigIgnoreApprovalEnabled)
}

func (p *externalCallsProvider) getFeatureFlag(flag string, org string) (bool, error) {
	conf := p.c.Engine().GetConfiguration().Clone()
	conf.Set(configuration.ORGANIZATION, org)
	return config_utils.GetFeatureFlagValue(flag, conf, p.c.Engine().GetNetworkAccess().GetHttpClient())
}

func (p *externalCallsProvider) getSastSettings(org string) (*sast_contract.SastResponse, error) {
	gafConfig := p.c.Engine().GetConfiguration().Clone()
	gafConfig.Set(configuration.ORGANIZATION, org)

	response, err := gafConfig.GetWithError(code.ConfigurationSastSettings)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch SAST settings for org %s: %w", org, err)
	}

	sastResponse, ok := response.(*sast_contract.SastResponse)
	if !ok {
		return nil, fmt.Errorf("failed to type assert SAST response for org %s", org)
	}

	return sastResponse, nil
}

func (p *externalCallsProvider) folderOrganization(path types.FilePath) string {
	return p.c.FolderOrganization(path)
}

type serviceImpl struct {
	c                 *config.Config
	provider          ExternalCallsProvider
	orgToFlag         *imcache.Cache[string, map[string]bool]
	orgToSastSettings *imcache.Cache[string, *sast_contract.SastResponse]
	mutex             *sync.Mutex
}

type Option func(*serviceImpl)

func WithProvider(provider ExternalCallsProvider) Option {
	return func(s *serviceImpl) {
		s.provider = provider
	}
}

func New(c *config.Config, opts ...Option) *serviceImpl {
	ffCache := imcache.New[string, map[string]bool]()
	sastResponseCache := imcache.New[string, *sast_contract.SastResponse]()

	// default values
	service := &serviceImpl{
		c:                 c,
		provider:          &externalCallsProvider{c: c},
		orgToFlag:         ffCache,
		orgToSastSettings: sastResponseCache,
		mutex:             &sync.Mutex{},
	}

	for _, opt := range opts {
		opt(service)
	}

	return service
}

func (s *serviceImpl) fetch(org string) map[string]bool {
	s.mutex.Lock()
	orgFlags, found := s.orgToFlag.Get(org)
	if found {
		clone := maps.Clone(orgFlags)
		s.mutex.Unlock()
		return clone
	}
	s.mutex.Unlock()
	orgFlags = make(map[string]bool)

	var wg sync.WaitGroup
	wg.Add(len(Flags))

	for _, flag := range Flags {
		go func() {
			defer wg.Done()

			var enabled bool
			var err error

			// Use provider to fetch config values
			if flag == IgnoreApprovalEnabled {
				enabled, err = s.provider.getIgnoreApprovalEnabled(org)
			} else {
				enabled, err = s.provider.getFeatureFlag(flag, org)
			}

			if err != nil {
				// TODO: wait until @startOfflineDetection is integrated. If error isn't related to network issues, there is nothing user can do anyway
				s.c.Logger().Err(err).Str("method", "GetFlags").Msgf("couldn't get config value %s", flag)
			}

			s.mutex.Lock()
			// Check if cache was flushed while we were fetching
			if orgFlags != nil {
				orgFlags[flag] = enabled
			}
			s.mutex.Unlock()
		}()
	}

	wg.Wait()

	s.mutex.Lock()
	s.orgToFlag.Set(org, orgFlags, imcache.WithExpiration(time.Minute))
	result := orgFlags
	s.mutex.Unlock()

	return result
}

func (s *serviceImpl) fetchSastSettings(org string) (*sast_contract.SastResponse, error) {
	s.mutex.Lock()
	cached, found := s.orgToSastSettings.Get(org)
	if found {
		s.mutex.Unlock()
		return cached, nil
	}
	s.mutex.Unlock()

	sastResponse, err := s.provider.getSastSettings(org)
	if err != nil {
		return nil, err
	}

	s.mutex.Lock()
	s.orgToSastSettings.Set(org, sastResponse, imcache.WithExpiration(time.Minute))
	s.mutex.Unlock()

	return sastResponse, nil
}

func (s *serviceImpl) FlushCache() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.orgToFlag.RemoveAll()
	s.orgToSastSettings.RemoveAll()
}

func (s *serviceImpl) GetFromStoredFolderConfig(folderPath types.FilePath, flag string) bool {
	folderConfig := s.c.FolderConfig(folderPath)
	v, ok := folderConfig.FeatureFlags[flag]
	if !ok {
		s.c.Logger().Warn().Str("method", "GetFromStoredFolderConfig").Msgf("feature flag %s not found in folder config for path %s", flag, folderPath)
		return false
	}

	return v
}

func (s *serviceImpl) PopulateFolderConfig(folderConfig *types.FolderConfig) {
	logger := s.c.Logger().With().Str("method", "PopulateFolderConfig").Str("folderPath", string(folderConfig.FolderPath)).Logger()
	org := s.provider.folderOrganization(folderConfig.FolderPath)

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
		logger.Err(sastErr).Msgf("couldn't get SAST settings for org %s", org)
	} else {
		folderConfig.SastSettings = sastSettings
	}

	err := storedconfig.UpdateFolderConfig(s.c.Engine().GetConfiguration(), folderConfig, &logger)
	if err != nil {
		logger.Err(err).Msgf("couldn't update folder config for path %s", folderConfig.FolderPath)
	}
}
