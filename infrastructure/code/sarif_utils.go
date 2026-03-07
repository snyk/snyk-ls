/*
 * © 2022 Snyk Limited All rights reserved.
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

package code

import (
	"github.com/snyk/code-client-go/llm"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
)

func newCodeRequestContext(c *config.Config, folderPath types.FilePath) codeRequestContext {
	unknown := "unknown"
	orgId := unknown

	// Try to get folder-specific organization first, fall back to global org
	if folderPath != "" {
		folderOrg := config.FolderOrganization(c.Engine().GetConfiguration(), folderPath, c.Logger())
		if folderOrg != "" {
			orgId = folderOrg
		}
	}

	return codeRequestContext{
		Initiator: "IDE",
		Flow:      "language-server",
		Org: codeRequestContextOrg{
			Name:        unknown,
			DisplayName: unknown,
			PublicId:    orgId,
		},
	}
}

func NewAutofixCodeRequestContext(c *config.Config, folderPath types.FilePath) llm.CodeRequestContext {
	ctx := newCodeRequestContext(c, folderPath)
	return llm.CodeRequestContext{
		Initiator: ctx.Initiator,
		Flow:      ctx.Flow,
		Org: llm.CodeRequestContextOrg{
			Name:        ctx.Org.Name,
			DisplayName: ctx.Org.DisplayName,
			PublicId:    ctx.Org.PublicId,
		},
	}
}

func GetAutofixIdeExtensionDetails(c *config.Config) llm.AutofixIdeExtensionDetails {
	return llm.AutofixIdeExtensionDetails{
		IdeName:          c.Engine().GetConfiguration().GetString(configuration.INTEGRATION_ENVIRONMENT),
		IdeVersion:       c.Engine().GetConfiguration().GetString(configuration.INTEGRATION_ENVIRONMENT_VERSION),
		ExtensionName:    c.Engine().GetConfiguration().GetString(configuration.INTEGRATION_NAME),
		ExtensionVersion: c.Engine().GetConfiguration().GetString(configuration.INTEGRATION_VERSION),
	}
}
