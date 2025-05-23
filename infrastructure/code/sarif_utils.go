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

	"github.com/snyk/snyk-ls/application/config"
)

func newCodeRequestContext() codeRequestContext {
	unknown := "unknown"
	orgId := unknown
	if config.CurrentConfig().Organization() != "" {
		orgId = config.CurrentConfig().Organization()
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

func NewAutofixCodeRequestContext() llm.CodeRequestContext {
	c := newCodeRequestContext()
	return llm.CodeRequestContext{
		Initiator: c.Initiator,
		Flow:      c.Flow,
		Org: llm.CodeRequestContextOrg{
			Name:        c.Org.Name,
			DisplayName: c.Org.DisplayName,
			PublicId:    c.Org.PublicId,
		},
	}
}

func GetAutofixIdeExtensionDetails(c *config.Config) llm.AutofixIdeExtensionDetails {
	return llm.AutofixIdeExtensionDetails{
		IdeName:          c.IdeName(),
		IdeVersion:       c.IdeVersion(),
		ExtensionName:    c.IntegrationName(),
		ExtensionVersion: c.IntegrationVersion(),
	}
}
