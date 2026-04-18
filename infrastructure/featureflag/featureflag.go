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
	"github.com/rs/zerolog"

	"github.com/snyk/code-client-go/pkg/code"
	"github.com/snyk/code-client-go/pkg/code/sast_contract"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/local_workflows/ignore_workflow"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
)

const (
	SnykCodeConsistentIgnores     string = "snykCodeConsistentIgnores"
	SnykCodeInlineIgnore          string = "snykCodeInlineIgnore"
	IgnoreApprovalEnabled         string = "internal_iaw_enabled"
	UseExperimentalRiskScoreInCLI string = "useExperimentalRiskScoreInCLI"
	UseExperimentalRiskScore      string = "useExperimentalRiskScore"
	UseOsTest                     string = "useTestShimForOSCliTest"
	SnykSecretsEnabled            string = "isSecretsEnabled"
	ScanCommandsEnabled           string = "internal_scanCommandsEnabled"
)

var Flags = []string{
	SnykCodeConsistentIgnores,
	SnykCodeInlineIgnore,
	IgnoreApprovalEnabled,
	UseExperimentalRiskScoreInCLI,
	UseExperimentalRiskScore,
	UseOsTest,
	SnykSecretsEnabled,
}

func UseOsTestWorkflow(folderConfig *types.FolderConfig) bool {
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
	GetFromFolderConfig(folderPath types.FilePath, flag string) bool
	PopulateFolderConfig(folderConfig *types.FolderConfig)
	FlushCache()
	// Override pins flag to value regardless of what the API returns.
	// Intended for tests that must prevent specific scanner paths from being triggered.
	Override(flag string, value bool)
}

type externalCallsProvider struct {
	conf   configuration.Configuration
	logger *zerolog.Logger
	engine workflow.Engine
}

func (p *externalCallsProvider) getIgnoreApprovalEnabled(org string) (bool, error) {
	conf := p.conf.Clone()
	conf.Set(configuration.ORGANIZATION, org)
	return conf.GetBoolWithError(ignore_workflow.ConfigIgnoreApprovalEnabled)
}

func (p *externalCallsProvider) getFeatureFlag(flag string, org string) (bool, error) {
	conf := p.conf.Clone()
	conf.Set(configuration.ORGANIZATION, org)
	return config_utils.GetFeatureFlagValue(flag, conf, p.engine.GetNetworkAccess().GetHttpClient())
}

func (p *externalCallsProvider) getSastSettings(org string) (*sast_contract.SastResponse, error) {
	engineConfig := p.conf.Clone()
	engineConfig.Set(configuration.ORGANIZATION, org)

	response, err := engineConfig.GetWithError(code.ConfigurationSastSettings)
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
	// Read the org from already-stored config values only — never trigger GAF's
	// /rest/self auto-determination. GAF's Get/GetString("org") calls the
	// defaultFuncOrganization callback on every invocation when the result is a
	// slug or the defaultCache is cleared (e.g. by processConfigSettings).
	//
	// Safe keys (no GAF default function registered):
	//   1. AutoDeterminedOrg: stored by LDX-Sync via SetAutoDeterminedOrg.
	//   2. PreferredOrg: stored by updateFolderOrgIfNeeded / user settings.
	//   3. UserGlobalKey(SettingOrganization): stored by SetOrganization.
	// If none of these are set, the org is unknown (e.g. LDX-Sync has not run
	// yet or failed with 401), and callers will handle the empty string.
	snapshot := types.ReadFolderConfigSnapshot(p.conf, path)
	if snapshot.OrgSetByUser && snapshot.PreferredOrg != "" {
		return snapshot.PreferredOrg
	}
	if snapshot.AutoDeterminedOrg != "" {
		return snapshot.AutoDeterminedOrg
	}
	// UserGlobalKey(SettingOrganization) is set by SetOrganization (explicit IDE/user setting).
	if s, ok := p.conf.Get(configresolver.UserGlobalKey(types.SettingOrganization)).(string); ok && s != "" {
		return s
	}
	return ""
}

type serviceImpl struct {
	conf              configuration.Configuration
	logger            *zerolog.Logger
	engine            workflow.Engine
	configResolver    types.ConfigResolverInterface
	provider          ExternalCallsProvider
	orgToFlag         *imcache.Cache[string, map[string]bool]
	orgToSastSettings *imcache.Cache[string, *sast_contract.SastResponse]
	mutex             *sync.Mutex
	overrides         map[string]bool
	overrideMu        sync.RWMutex
}

type Option func(*serviceImpl)

func WithProvider(provider ExternalCallsProvider) Option {
	return func(s *serviceImpl) {
		s.provider = provider
	}
}

func New(conf configuration.Configuration, logger *zerolog.Logger, engine workflow.Engine, configResolver types.ConfigResolverInterface, opts ...Option) *serviceImpl {
	ffCache := imcache.New[string, map[string]bool]()
	sastResponseCache := imcache.New[string, *sast_contract.SastResponse]()

	// default values
	service := &serviceImpl{
		conf:              conf,
		logger:            logger,
		engine:            engine,
		configResolver:    configResolver,
		provider:          &externalCallsProvider{conf: conf, logger: logger, engine: engine},
		orgToFlag:         ffCache,
		orgToSastSettings: sastResponseCache,
		mutex:             &sync.Mutex{},
		overrides:         make(map[string]bool),
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
		s.logger.Debug().Str("org", org).Interface("cachedFlags", clone).Msg("feature flags cache hit")
		return clone
	}
	s.mutex.Unlock()
	s.logger.Debug().Str("org", org).Msg("feature flags cache miss, fetching from API")
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
				s.logger.Err(err).Str("method", "GetFlags").Str("org", org).Str("flag", flag).Msgf("couldn't get config value %s", flag)
			} else {
				s.logger.Debug().Str("method", "GetFlags").Str("org", org).Str("flag", flag).Bool("enabled", enabled).Msg("feature flag result")
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

func (s *serviceImpl) Override(flag string, value bool) {
	s.overrideMu.Lock()
	defer s.overrideMu.Unlock()
	s.overrides[flag] = value
}

func (s *serviceImpl) GetFromFolderConfig(folderPath types.FilePath, flag string) bool {
	folderConfig := config.GetFolderConfigFromEngine(s.engine, s.configResolver, folderPath, s.logger)
	return folderConfig.GetFeatureFlag(flag)
}

func (s *serviceImpl) PopulateFolderConfig(folderConfig *types.FolderConfig) {
	logger := s.logger.With().Str("method", "PopulateFolderConfig").Str("folderPath", string(folderConfig.FolderPath)).Logger()
	org := s.provider.folderOrganization(folderConfig.FolderPath)
	logger.Debug().Str("resolvedOrg", org).Msg("resolved org for feature flag fetch")

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

	// Write feature flags to configuration under folder metadata prefix keys
	for name, value := range flags {
		folderConfig.SetFeatureFlag(name, value)
	}
	logger.Debug().Str("org", org).Interface("flags", flags).Msg("feature flags fetched")

	// Apply overrides last so they always win over API-returned values.
	s.overrideMu.RLock()
	for name, value := range s.overrides {
		folderConfig.SetFeatureFlag(name, value)
	}
	s.overrideMu.RUnlock()

	if sastErr != nil {
		logger.Err(sastErr).Msgf("couldn't get SAST settings for org %s", org)
	} else {
		types.SetSastSettings(s.conf, folderConfig.FolderPath, sastSettings)
	}
}
