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
	"encoding/json"
	"fmt"

	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/ignore_workflow"
)

type submitIgnoreRequest struct {
	command       types.CommandData
	issueProvider snyk.IssueProvider
	c             *config.Config
}

func (cmd *submitIgnoreRequest) Command() types.CommandData {
	return cmd.command
}

func (cmd *submitIgnoreRequest) Execute(_ context.Context) (any, error) {
	engine := cmd.c.Engine()
	workflowType, ok := cmd.command.Arguments[0].(string)
	if !ok {
		return nil, fmt.Errorf("workflow type should be a string")
	}
	issueId, ok := cmd.command.Arguments[1].(string)
	if !ok {
		return nil, fmt.Errorf("issueId type should be a string")
	}

	//TODO remove this loop when testing is done.
	issueId = ""
	for _, issueList := range cmd.issueProvider.Issues() {
		for _, issue := range issueList {
			if issue.GetFilterableIssueType() == product.FilterableIssueTypeCodeSecurity {
				issueId = issue.GetAdditionalData().GetKey()
				break
			}
		}
	}

	issue := cmd.issueProvider.Issue(issueId)
	if issue == nil {
		return nil, fmt.Errorf("issue not found")
	}

	findingsId := issue.GetFindingsId()
	contentRoot := issue.GetContentRoot()

	switch workflowType {
	case "create":
		gafConfig, err := cmd.createCreateConfiguration(engine, findingsId, contentRoot)
		if err != nil {
			return nil, err
		}

		response, err := engine.InvokeWithConfig(ignore_workflow.WORKFLOWID_IGNORE_CREATE, gafConfig)
		if err != nil {
			return nil, err
		}

		if len(response) == 0 {
			return nil, fmt.Errorf("no data returned from ignore workflow")
		}

		output, ok := response[0].GetPayload().([]byte)
		if !ok {
			return nil, fmt.Errorf("invalid response from ignore workflow") //TODO fix this
		}

		err = updateIssueWithIgnoreDetails(output, issue)
		if err != nil {
			return nil, err
		}

	case "update":
		gafConfig, err := cmd.createEditConfigurations(engine, findingsId, contentRoot)
		if err != nil {
			return nil, err
		}

		response, err := engine.InvokeWithConfig(ignore_workflow.WORKFLOWID_IGNORE_CREATE, gafConfig)
		if err != nil {
			return nil, err
		}

		if len(response) == 0 {
			return nil, fmt.Errorf("no data returned from ignore workflow")
		}

		output, ok := response[0].GetPayload().([]byte)
		if !ok {
			return nil, fmt.Errorf("invalid response from ignore workflow") //TODO fix this
		}

		err = updateIssueWithIgnoreDetails(output, issue)
		if err != nil {
			return nil, err
		}

	case "delete":
		gafConfig, err := cmd.createDeleteConfiguration(engine, findingsId, contentRoot)
		if err != nil {
			return nil, err
		}

		response, err := engine.InvokeWithConfig(ignore_workflow.WORKFLOWID_IGNORE_CREATE, gafConfig)
		if err != nil {
			return nil, err
		}

		if len(response) == 0 {
			return nil, fmt.Errorf("no data returned from ignore workflow")
		}

		output, ok := response[0].GetPayload().([]byte)
		if !ok {
			return nil, fmt.Errorf("invalid response from ignore workflow") //TODO fix this
		}

		err = updateIssueWithIgnoreDetails(output, issue)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf(`unknown worflow`)
	}

	return nil, nil
}

func (cmd *submitIgnoreRequest) createCreateConfiguration(engine workflow.Engine, findingsId string, contentRoot types.FilePath) (configuration.Configuration, error) {
	if len(cmd.command.Arguments) < 5 {
		return nil, fmt.Errorf("insufficient arguments for ignore-create workflow")
	}

	ignoreType, ok := cmd.command.Arguments[2].(string)
	if !ok {
		return nil, fmt.Errorf("ignoreType should be a string")
	}
	reason, ok := cmd.command.Arguments[3].(string)
	if !ok {
		return nil, fmt.Errorf("reason should be a string")
	}
	expiration, ok := cmd.command.Arguments[4].(string)
	if !ok {
		return nil, fmt.Errorf("expiration should be a string")
	}

	gafConfig := engine.GetConfiguration().Clone()
	gafConfig.Set(ignore_workflow.FindingsIdKey, findingsId)
	gafConfig.Set(ignore_workflow.IgnoreTypeKey, ignoreType)
	gafConfig.Set(ignore_workflow.ReasonKey, reason)
	gafConfig.Set(ignore_workflow.ExpirationKey, expiration)
	gafConfig.Set(ignore_workflow.EnrichResponseKey, true)
	gafConfig.Set(ignore_workflow.InteractiveKey, false)
	gafConfig.Set(configuration.INPUT_DIRECTORY, contentRoot)
	return gafConfig, nil
}

func (cmd *submitIgnoreRequest) createEditConfigurations(engine workflow.Engine, findingsId string, contentRoot types.FilePath) (configuration.Configuration, error) {
	if len(cmd.command.Arguments) < 5 {
		return nil, fmt.Errorf("insufficient arguments for ignore-edit workflow")
	}

	ignoreType, ok := cmd.command.Arguments[2].(string)
	if !ok {
		return nil, fmt.Errorf("ignoreType should be a string")
	}
	reason, ok := cmd.command.Arguments[3].(string)
	if !ok {
		return nil, fmt.Errorf("reason should be a string")
	}
	expiration, ok := cmd.command.Arguments[4].(string)
	if !ok {
		return nil, fmt.Errorf("expiration should be a string")
	}
	ignoreId, ok := cmd.command.Arguments[5].(string)
	if !ok {
		return nil, fmt.Errorf("ignoreId should be a string")
	}

	gafConfig := engine.GetConfiguration().Clone()
	gafConfig.Set(ignore_workflow.FindingsIdKey, findingsId)
	gafConfig.Set(ignore_workflow.IgnoreTypeKey, ignoreType)
	gafConfig.Set(ignore_workflow.ReasonKey, reason)
	gafConfig.Set(ignore_workflow.ExpirationKey, expiration)
	gafConfig.Set(ignore_workflow.EnrichResponseKey, true)
	gafConfig.Set(ignore_workflow.InteractiveKey, false)
	gafConfig.Set(ignore_workflow.IgnoreIdKey, ignoreId)
	gafConfig.Set(configuration.INPUT_DIRECTORY, contentRoot)
	return gafConfig, nil
}

func (cmd *submitIgnoreRequest) createDeleteConfiguration(engine workflow.Engine, findingsId string, contentRoot types.FilePath) (configuration.Configuration, error) {
	if len(cmd.command.Arguments) < 3 {
		return nil, fmt.Errorf("insufficient arguments for ignore-delete workflow")
	}

	ignoreId, ok := cmd.command.Arguments[5].(string)
	if !ok {
		return nil, fmt.Errorf("ignoreId should be a string")
	}

	gafConfig := engine.GetConfiguration().Clone()
	gafConfig.Set(ignore_workflow.FindingsIdKey, findingsId) //TODO remove this one?
	gafConfig.Set(ignore_workflow.IgnoreIdKey, ignoreId)
	gafConfig.Set(ignore_workflow.EnrichResponseKey, true)
	gafConfig.Set(ignore_workflow.InteractiveKey, false)
	gafConfig.Set(configuration.INPUT_DIRECTORY, contentRoot)
	return gafConfig, nil
}

func updateIssueWithIgnoreDetails(output []byte, issue types.Issue) error {
	var suppression sarif.Suppression
	err := json.Unmarshal(output, &suppression)
	if err != nil {
		return err
	}
	ignoreDetails := code.SarifSuppressionToIgnoreDetails(&suppression)

	issue.SetIgnoreDetails(ignoreDetails)
	return nil
}
