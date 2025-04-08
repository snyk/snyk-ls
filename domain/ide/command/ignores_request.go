/*
 * © 2023 Snyk Limited
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
	"fmt"

	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/types"
)

type submitIgnoreRequest struct {
	command       types.CommandData
	issueProvider snyk.IssueProvider
	c             *config.Config
}

type IgnoresResponse struct {
	SuppressionStatus string
}

func (cmd *submitIgnoreRequest) Command() types.CommandData {
	return cmd.command
}

func (cmd *submitIgnoreRequest) Execute(ctx context.Context) (any, error) {
	engine := cmd.c.Engine()
	workflowType, ok := cmd.command.Arguments[0].(string)
	if !ok {
		return nil, fmt.Errorf("workflow type should be a string")
	}

	switch workflowType {
	case "create":
		if len(cmd.command.Arguments) < 7 {
			return nil, fmt.Errorf("insufficient arguments for ignore-create workflow")
		}

		issue := cmd.issueProvider.Issue(cmd.command.Arguments[1].(string))

		findingsId := issue.GetFindingsId()

		gafConfig := engine.GetConfiguration().Clone()
		gafConfig.Set("id", findingsId)
		gafConfig.Set("ignoreType", cmd.command.Arguments[2].(string))
		gafConfig.Set("reason", cmd.command.Arguments[3].(string))
		gafConfig.Set("expiration", cmd.command.Arguments[4].(string))
		gafConfig.Set("enrichResponse", true)
		gafConfig.Set("interactive", false)

		result, err := engine.InvokeWithConfig(localworkflows.WORKFLOWID_IGNORE_CREATE, gafConfig)
		if err != nil && len(result) == 0 {
			return nil, fmt.Errorf("failed to invoke ignore-create workflow: %w", err)
		}

		response := result[0].GetPayload().(IgnoresResponse)
		issue.SetSuppressionStatus(response.SuppressionStatus)

	case "update":
		if len(cmd.command.Arguments) < 8 {
			return nil, fmt.Errorf("insufficient arguments for ignore-edit workflow")
		}

		issue := cmd.issueProvider.Issue(cmd.command.Arguments[1].(string))
		findingsId := issue.GetFindingsId()

		gafConfig := engine.GetConfiguration().Clone()
		gafConfig.Set("id", findingsId)
		gafConfig.Set("ignoreType", cmd.command.Arguments[2].(string))
		gafConfig.Set("reason", cmd.command.Arguments[3].(string))
		gafConfig.Set("expiration", cmd.command.Arguments[4].(string))
		gafConfig.Set("enrichResponse", true)
		gafConfig.Set("interactive", false)

		result, err := engine.InvokeWithConfig(localworkflows.WORKFLOWID_IGNORE_EDIT, gafConfig)
		if err != nil && len(result) == 0 {
			return nil, fmt.Errorf("failed to invoke ignore-create workflow: %w", err)
		}

		response := result[0].GetPayload().(IgnoresResponse)
		issue.SetSuppressionStatus(response.SuppressionStatus)

	case "delete":
		if len(cmd.command.Arguments) < 3 {
			return nil, fmt.Errorf("insufficient arguments for ignore-delete workflow")
		}

		issue := cmd.issueProvider.Issue(cmd.command.Arguments[1].(string))
		findingsId := issue.GetFindingsId()

		gafConfig := engine.GetConfiguration().Clone()
		gafConfig.Set("id", findingsId)
		gafConfig.Set("enrichResponse", true)
		gafConfig.Set("interactive", false)

		result, err := engine.InvokeWithConfig(localworkflows.WORKFLOWID_IGNORE_DELETE, gafConfig)
		if err != nil && len(result) == 0 {
			return nil, fmt.Errorf("failed to invoke ignore-create workflow: %w", err)
		}

		response := result[0].GetPayload().(IgnoresResponse)
		issue.SetSuppressionStatus(response.SuppressionStatus)

	default:
		return nil, fmt.Errorf(`unkown worflow`)
	}

	return nil, nil
}
