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

var Flags = []string{
	SnykCodeConsistentIgnores,
	SnykCodeInlineIgnore,
}

type Service interface {
	GetFromFolderConfig(folderPath types.FilePath, flag string) bool
	PopulateFolderConfig(folderConfig *types.FolderConfig)
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

func (s *serviceImpl) fetch(org string) map[string]bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.orgToFlag[org] != nil {
		return s.orgToFlag[org]
	}

	s.orgToFlag[org] = make(map[string]bool)
	for _, flag := range Flags {
		conf := s.c.Engine().GetConfiguration().Clone()
		conf.Set(configuration.ORGANIZATION, org)
		httpClient := s.c.Engine().GetNetworkAccess().GetHttpClient()
		enabled, err := config_utils.GetFeatureFlagValue(flag, conf, httpClient)
		if err != nil {
			// TODO: wait until @startOfflineDetection is integrated. If error isn't related to network issues, there is nothing user can do anyway
			s.c.Logger().Err(err).Str("method", "GetFlags").Msgf("couldn't get feature flag %s", flag)
		}
		s.orgToFlag[org][flag] = enabled
	}
	return s.orgToFlag[org]
}

func (s *serviceImpl) FlushCache() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.orgToFlag = make(map[string]map[string]bool)
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

func (s *serviceImpl) PopulateFolderConfig(folderConfig *types.FolderConfig) {
	org := s.c.FolderOrganization(folderConfig.FolderPath)
	flags := s.fetch(org)
	folderConfig.FeatureFlags = flags
}
