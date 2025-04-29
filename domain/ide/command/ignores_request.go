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
	"context"
	"encoding/json"
	"fmt"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/analytics"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"

	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/ignore_workflow"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	workflowTypeIndex = iota
	issueIdIndex
	ignoreTypeIndex
	reasonIndex
	expirationIndex
	ignoreIdIndex
)

type submitIgnoreRequest struct {
	command       types.CommandData
	issueProvider snyk.IssueProvider
	notifier      notification.Notifier
	srv           types.Server
	c             *config.Config
}

func (cmd *submitIgnoreRequest) Command() types.CommandData {
	return cmd.command
}

func (cmd *submitIgnoreRequest) Execute(ctx context.Context) (any, error) {
	logger := cmd.c.Logger().With().Str("method", "submitIgnoreRequest.Execute").Logger()
	workflowType, ok := cmd.command.Arguments[workflowTypeIndex].(string)
	if !ok {
		return nil, fmt.Errorf("workflow type should be a string")
	}
	issueId, ok := cmd.command.Arguments[issueIdIndex].(string)
	if !ok {
		return nil, fmt.Errorf("issueId type should be a string")
	}

	issue := cmd.issueProvider.Issue(issueId)
	if issue == nil {
		return nil, fmt.Errorf("issue not found")
	}

	findingId := issue.GetFindingId()
	contentRoot := issue.GetContentRoot()
	engine := cmd.c.Engine()

	switch workflowType {
	case "create":
		err := cmd.createIgnoreRequest(engine, findingId, contentRoot, issue)
		if err != nil {
			return nil, err
		}

	case "update":
		err := cmd.editIgnoreRequest(engine, contentRoot, issue)
		if err != nil {
			return nil, err
		}

	case "delete":
		err := cmd.deleteIgnoreRequest(engine, contentRoot, issue)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf(`unknown workflow`)
	}

	SendShowDocumentRequest(ctx, logger, issue, cmd.srv)

	return nil, nil
}

func (cmd *submitIgnoreRequest) createIgnoreRequest(engine workflow.Engine, findingsId string, contentRoot types.FilePath, issue types.Issue) error {
	gafConfig, err := cmd.initializeCreateConfiguration(engine.GetConfiguration().Clone(), findingsId, contentRoot)
	if err != nil {
		return err
	}

	err = cmd.executeIgnoreWorkflow(engine, ignore_workflow.WORKFLOWID_IGNORE_CREATE, gafConfig, issue)
	cmd.sendIgnoreRequestAnalytics(err)

	return err
}

func (cmd *submitIgnoreRequest) initializeCreateConfiguration(gafConfig configuration.Configuration, findingId string, contentRoot types.FilePath) (configuration.Configuration, error) {
	if len(cmd.command.Arguments) < 5 {
		return nil, fmt.Errorf("insufficient arguments for ignore-create workflow")
	}

	ignoreType, reason, expiration, err := GetCommandArgs(cmd)
	if err != nil {
		return nil, err
	}

	gafConfig.Set(ignore_workflow.FindingsIdKey, findingId)
	gafConfig = initializeBaseConfiguration(gafConfig, contentRoot)
	gafConfig = addCreateAndUpdateConfiguration(gafConfig, ignoreType, reason, expiration)

	return gafConfig, nil
}

func (cmd *submitIgnoreRequest) editIgnoreRequest(engine workflow.Engine, contentRoot types.FilePath, issue types.Issue) error {
	gafConfig, err := cmd.initializeEditConfigurations(engine.GetConfiguration().Clone(), contentRoot)
	if err != nil {
		return err
	}

	err = cmd.executeIgnoreWorkflow(engine, ignore_workflow.WORKFLOWID_IGNORE_EDIT, gafConfig, issue)
	if err != nil {
		return err
	}
	return nil
}

func (cmd *submitIgnoreRequest) initializeEditConfigurations(gafConfig configuration.Configuration, contentRoot types.FilePath) (configuration.Configuration, error) {
	if len(cmd.command.Arguments) < 5 {
		return nil, fmt.Errorf("insufficient arguments for ignore-edit workflow")
	}

	ignoreType, reason, expiration, err := GetCommandArgs(cmd)
	if err != nil {
		return nil, err
	}

	ignoreId, err := getIgnoreIdFromCmdArgs(cmd)
	if err != nil {
		return nil, err
	}

	gafConfig = initializeBaseConfiguration(gafConfig, contentRoot)
	gafConfig = addCreateAndUpdateConfiguration(gafConfig, ignoreType, reason, expiration)
	gafConfig.Set(ignore_workflow.IgnoreIdKey, ignoreId)

	return gafConfig, nil
}

func (cmd *submitIgnoreRequest) deleteIgnoreRequest(engine workflow.Engine, contentRoot types.FilePath, issue types.Issue) error {
	gafConfig, err := cmd.initializeDeleteConfiguration(engine.GetConfiguration().Clone(), contentRoot)
	if err != nil {
		return err
	}

	err = cmd.executeIgnoreWorkflow(engine, ignore_workflow.WORKFLOWID_IGNORE_DELETE, gafConfig, issue)
	if err != nil {
		return err
	}
	return nil
}

func (cmd *submitIgnoreRequest) initializeDeleteConfiguration(gafConfig configuration.Configuration, contentRoot types.FilePath) (configuration.Configuration, error) {
	if len(cmd.command.Arguments) < 3 {
		return nil, fmt.Errorf("insufficient arguments for ignore-delete workflow")
	}

	ignoreId, ok := cmd.command.Arguments[2].(string)
	if !ok {
		return nil, fmt.Errorf("ignoreId should be a string")
	}

	gafConfig = initializeBaseConfiguration(gafConfig, contentRoot)
	gafConfig.Set(ignore_workflow.IgnoreIdKey, ignoreId)

	return gafConfig, nil
}

func getIgnoreIdFromCmdArgs(cmd *submitIgnoreRequest) (string, error) {
	if len(cmd.command.Arguments) <= ignoreIdIndex {
		return "", fmt.Errorf("missing ignoreId")
	}
	ignoreId, ok := cmd.command.Arguments[ignoreIdIndex].(string)
	if !ok {
		return "", fmt.Errorf("ignoreId should be a string")
	}
	return ignoreId, nil
}

func GetCommandArgs(cmd *submitIgnoreRequest) (ignoreType string, reason string, expiration string, err error) {
	if len(cmd.command.Arguments) < 5 {
		return "", "", "", fmt.Errorf("insufficient arguments for ignore command")
	}
	ignoreType, err = getStringArgument(cmd, ignoreTypeIndex, "ignoreType")
	if err != nil {
		return "", "", "", err
	}
	reason, err = getStringArgument(cmd, reasonIndex, "reason")
	if err != nil {
		return "", "", "", err
	}
	expiration, err = getStringArgument(cmd, expirationIndex, "expiration")
	if err != nil {
		return "", "", "", err
	}

	return ignoreType, reason, expiration, nil
}

func getStringArgument(cmd *submitIgnoreRequest, index int, argName string) (string, error) {
	if len(cmd.command.Arguments) <= index {
		return "", fmt.Errorf("missing argument: %s", argName)
	}
	arg, ok := cmd.command.Arguments[index].(string)
	if !ok {
		return "", fmt.Errorf("%s should be a string", argName)
	}
	return arg, nil
}

func initializeBaseConfiguration(gafConfig configuration.Configuration, contentRoot types.FilePath) configuration.Configuration {
	gafConfig.Set(ignore_workflow.EnrichResponseKey, true)
	gafConfig.Set(ignore_workflow.InteractiveKey, false)
	gafConfig.Set(configuration.INPUT_DIRECTORY, string(contentRoot))
	return gafConfig
}

func addCreateAndUpdateConfiguration(gafConfig configuration.Configuration, ignoreType string, reason string, expiration string) configuration.Configuration {
	gafConfig.Set(ignore_workflow.IgnoreTypeKey, ignoreType)
	gafConfig.Set(ignore_workflow.ReasonKey, reason)
	gafConfig.Set(ignore_workflow.ExpirationKey, expiration)
	return gafConfig
}

func updateIssueWithIgnoreDetails(output []byte, issue types.Issue) error {
	var suppression sarif.Suppression
	err := json.Unmarshal(output, &suppression)
	if err != nil {
		return err
	}
	isIgnored, ignoreDetails := code.GetIgnoreDetailsFromSuppressions([]sarif.Suppression{suppression})

	issue.SetIgnored(isIgnored)
	issue.SetIgnoreDetails(ignoreDetails)
	return nil
}

func (cmd *submitIgnoreRequest) executeIgnoreWorkflow(engine workflow.Engine, workflowId workflow.Identifier, gafConfig configuration.Configuration, issue types.Issue) error {
	response, err := engine.InvokeWithConfig(workflowId, gafConfig)
	if err != nil {
		return err
	}

	if len(response) == 0 {
		return fmt.Errorf("no data returned from ignore workflow")
	}

	output, ok := response[0].GetPayload().([]byte)
	if !ok {
		return fmt.Errorf("invalid response from ignore workflow")
	}

	err = updateIssueWithIgnoreDetails(output, issue)
	if err != nil {
		return err
	}
	return nil
}

func (cmd *submitIgnoreRequest) sendIgnoreRequestAnalytics(err error) {
	event := analytics.NewAnalyticsEventParam("Create ignore", err)
	analytics.SendAnalytics(cmd.c, event, err)
}
