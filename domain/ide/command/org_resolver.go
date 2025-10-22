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

package command

import (
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

//go:generate go tool github.com/golang/mock/mockgen -source=org_resolver.go -destination=mock_command/org_resolver_mock.go -package=mock_command

// OrgResolver defines the interface for organization resolution
type OrgResolver interface {
	ResolveOrganization(config configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, dir string) (ldx_sync_config.Organization, error)
}

// LDXSyncOrgResolver implements the OrgResolver interface using the GAF ldx_sync_config package
type LDXSyncOrgResolver struct{}

var _ OrgResolver = (*LDXSyncOrgResolver)(nil)

// NewLDXSyncOrgResolver creates a new LDXSyncOrgResolver
func NewLDXSyncOrgResolver() OrgResolver {
	return &LDXSyncOrgResolver{}
}

// ResolveOrganization resolves the organization for a given directory
func (r *LDXSyncOrgResolver) ResolveOrganization(config configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, dir string) (ldx_sync_config.Organization, error) {
	return ldx_sync_config.ResolveOrganization(config, engine, logger, dir, "")
}
