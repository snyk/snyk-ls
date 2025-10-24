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
	"sync"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
)

const (
	SnykCodeConsistentIgnores string = "snykCodeConsistentIgnores"
	SnykCodeInlineIgnore      string = "snykCodeInlineIgnore"
)

var flags = []string{
	SnykCodeConsistentIgnores,
	SnykCodeInlineIgnore,
}

type Service interface {
	Fetch(org string) (map[string]bool, error)
	GetFromFolderConfig(folderPath types.FilePath, flag string) (bool, bool)
	PopulateFolderConfig(folderConfig *types.FolderConfig) bool
	FlushCache()
}

type serviceImpl struct {
	c         *config.Config
	orgToFlag map[string]map[string]bool
	mutex     *sync.Mutex
}

func New(c *config.Config) Service {
	return &serviceImpl{
		c:         c,
		orgToFlag: make(map[string]map[string]bool),
		mutex:     &sync.Mutex{},
	}
}

func (s *serviceImpl) Fetch(org string) (map[string]bool, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.orgToFlag[org] != nil {
		return s.orgToFlag[org], nil
	}

	s.orgToFlag[org] = make(map[string]bool)
	for _, flag := range flags {
		conf := s.c.Engine().GetConfiguration().Clone()
		conf.Set(configuration.ORGANIZATION, org)
		httpClient := s.c.Engine().GetNetworkAccess().GetHttpClient()
		enabled, err := config_utils.GetFeatureFlagValue(flag, conf, httpClient)
		if err != nil {
			s.c.Logger().Err(err).Str("method", "GetFlags").Msgf("couldn't get feature flag %s", flag)
		}
		s.orgToFlag[org][flag] = enabled
	}
	return s.orgToFlag[org], nil
}

func (s *serviceImpl) FlushCache() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.orgToFlag = make(map[string]map[string]bool)
}

func (s *serviceImpl) GetFromFolderConfig(folderPath types.FilePath, flag string) (bool, bool) {
	folderConfig := s.c.FolderConfig(folderPath)
	v, ok := folderConfig.FeatureFlags[flag]
	return v, ok
}

func (s *serviceImpl) PopulateFolderConfig(folderConfig *types.FolderConfig) bool {
	logger := s.c.Logger().With().Str("method", "PopulateFeatureFlags").Logger()
	org := s.c.FolderOrganization(folderConfig.FolderPath)
	flags, err := s.Fetch(org)
	if err != nil {
		logger.Err(err).Msg("couldn't get feature flags")
		return false
	}
	folderConfig.FeatureFlags = flags
	return true
}
