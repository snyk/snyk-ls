/*
 * © 2024 Snyk Limited
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
	"context"
	"errors"

	"github.com/rs/zerolog"
	"github.com/snyk/code-client-go/llm"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/infrastructure/iac"
	"github.com/snyk/snyk-ls/infrastructure/oss"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

type generateIssueDescription struct {
	command            types.CommandData
	issueProvider      snyk.IssueProvider
	deepCodeLLMBinding llm.DeepCodeLLMBinding
}

func (cmd *generateIssueDescription) Command() types.CommandData {
	return cmd.command
}

func (cmd *generateIssueDescription) Execute(_ context.Context) (any, error) {
	c := config.CurrentConfig()
	logger := c.Logger().With().Str("method", "generateIssueDescription.Execute").Logger()
	args := cmd.command.Arguments

	issueId, ok := args[0].(string)
	if !ok {
		return nil, errors.New("failed to parse issue id")
	}

	issue := cmd.issueProvider.Issue(issueId)
	if issue.ID == "" {
		return nil, errors.New("failed to find issue")
	}

	if issue.Product == product.ProductInfrastructureAsCode {
		return getIacHtml(c, logger, issue)
	} else if issue.Product == product.ProductCode {
		return getCodeHtml(c, logger, issue, cmd.deepCodeLLMBinding)
	} else if issue.Product == product.ProductOpenSource {
		return getOssHtml(c, logger, issue)
	}

	return nil, nil
}

func getOssHtml(c *config.Config, logger zerolog.Logger, issue snyk.Issue) (string, error) {
	htmlRender, err := oss.NewHtmlRenderer(c)
	if err != nil {
		logger.Err(err).Msg("Cannot create Oss HTML render")
		return "", err
	}
	html := htmlRender.GetDetailsHtml(issue)
	return html, nil
}

func getCodeHtml(c *config.Config, logger zerolog.Logger, issue snyk.Issue, deepCodeLLMBinding llm.DeepCodeLLMBinding) (string, error) {
	htmlRender, err := code.GetHTMLRenderer(c, deepCodeLLMBinding)
	if err != nil {
		logger.Err(err).Msg("Cannot create Code HTML render")
		return "", err
	}
	html := htmlRender.GetDetailsHtml(issue)
	return html, nil
}

func getIacHtml(c *config.Config, logger zerolog.Logger, issue snyk.Issue) (string, error) {
	htmlRender, err := iac.NewHtmlRenderer(c)
	if err != nil {
		logger.Err(err).Msg("Cannot create IaC HTML render")
		return "", err
	}
	html := htmlRender.GetDetailsHtml(issue)
	return html, nil
}
