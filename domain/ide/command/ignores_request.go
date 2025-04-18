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

	"github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"

	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/ignore_workflow"
	"github.com/snyk/go-application-framework/pkg/workflow"
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

func (cmd *submitIgnoreRequest) Execute(_ context.Context) (any, error) {
	workflowType, ok := cmd.command.Arguments[0].(string)
	if !ok {
		return nil, fmt.Errorf("workflow type should be a string")
	}
	issueId, ok := cmd.command.Arguments[1].(string)
	if !ok {
		return nil, fmt.Errorf("issueId type should be a string")
	}

	issue := cmd.issueProvider.Issue(issueId)
	if issue == nil {
		return nil, fmt.Errorf("issue not found")
	}

	findingsId := issue.GetFindingId()
	contentRoot := issue.GetContentRoot()
	engine := cmd.c.Engine()

	switch workflowType {
	case "create":
		err := cmd.createIgnoreRequest(engine, findingsId, contentRoot, issue)
		if err != nil {
			return nil, err
		}

	case "update":
		err := cmd.editIgnoreRequest(engine, findingsId, contentRoot, issue)
		if err != nil {
			return nil, err
		}

	case "delete":
		err := cmd.deleteIgnoreRequest(engine, findingsId, contentRoot, issue)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf(`unknown workflow`)
	}

	cmd.sendShowDocumentRequest(issue)

	return nil, nil
}

func (cmd *submitIgnoreRequest) createIgnoreRequest(engine workflow.Engine, findingsId string, contentRoot types.FilePath, issue types.Issue) error {
	gafConfig, err := cmd.createTheCreateConfiguration(engine, findingsId, contentRoot)
	if err != nil {
		return err
	}

	response, err := engine.InvokeWithConfig(ignore_workflow.WORKFLOWID_IGNORE_CREATE, gafConfig)
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

	err = updateIssueWithIgnoreDetails(cmd.c, output, issue)
	if err != nil {
		return err
	}
	return nil
}

func (cmd *submitIgnoreRequest) createTheCreateConfiguration(engine workflow.Engine, findingsId string, contentRoot types.FilePath) (configuration.Configuration, error) {
	if len(cmd.command.Arguments) < 5 {
		return nil, fmt.Errorf("insufficient arguments for ignore-create workflow")
	}

	ignoreType, reason, expiration, err := GetCommandArgs(cmd)
	if err != nil {
		return nil, err
	}

	gafConfig := createBaseConfiguration(engine, findingsId, contentRoot)
	gafConfig = addUpdateConfiguration(gafConfig, ignoreType, reason, expiration)

	return gafConfig, nil
}

func (cmd *submitIgnoreRequest) editIgnoreRequest(engine workflow.Engine, findingsId string, contentRoot types.FilePath, issue types.Issue) error {
	gafConfig, err := cmd.createTheEditConfigurations(engine, findingsId, contentRoot)
	if err != nil {
		return err
	}

	response, err := engine.InvokeWithConfig(ignore_workflow.WORKFLOWID_IGNORE_CREATE, gafConfig)
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

	err = updateIssueWithIgnoreDetails(cmd.c, output, issue)
	if err != nil {
		return err
	}
	return nil
}

func (cmd *submitIgnoreRequest) createTheEditConfigurations(engine workflow.Engine, findingsId string, contentRoot types.FilePath) (configuration.Configuration, error) {
	if len(cmd.command.Arguments) < 5 {
		return nil, fmt.Errorf("insufficient arguments for ignore-edit workflow")
	}

	ignoreType, reason, expiration, err := GetCommandArgs(cmd)
	if err != nil {
		return nil, err
	}

	ignoreId, err2 := getIgnoreIdFromCmdArgs(cmd)
	if err2 != nil {
		return nil, err2
	}

	gafConfig := createBaseConfiguration(engine, findingsId, contentRoot)
	gafConfig = addUpdateConfiguration(gafConfig, ignoreType, reason, expiration)

	gafConfig.Set(ignore_workflow.IgnoreIdKey, ignoreId)

	return gafConfig, nil
}

func getIgnoreIdFromCmdArgs(cmd *submitIgnoreRequest) (string, error) {
	ignoreId, ok := cmd.command.Arguments[5].(string)
	if !ok {
		return "", fmt.Errorf("ignoreId should be a string")
	}
	return ignoreId, nil
}

func GetCommandArgs(cmd *submitIgnoreRequest) (string, string, string, error) {
	ignoreType, ok := cmd.command.Arguments[2].(string)
	if !ok {
		return "", "", "", fmt.Errorf("ignoreType should be a string")
	}
	reason, ok := cmd.command.Arguments[3].(string)
	if !ok {
		return "", "", "", fmt.Errorf("reason should be a string")
	}
	expiration, ok := cmd.command.Arguments[4].(string)
	if !ok {
		return "", "", "", fmt.Errorf("expiration should be a string")
	}

	return ignoreType, reason, expiration, nil
}

func (cmd *submitIgnoreRequest) deleteIgnoreRequest(engine workflow.Engine, findingsId string, contentRoot types.FilePath, issue types.Issue) error {
	gafConfig, err := cmd.createTheDeleteConfiguration(engine, findingsId, contentRoot)
	if err != nil {
		return err
	}

	response, err := engine.InvokeWithConfig(ignore_workflow.WORKFLOWID_IGNORE_CREATE, gafConfig)
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

	err = updateIssueWithIgnoreDetails(cmd.c, output, issue)
	if err != nil {
		return err
	}
	return nil
}

func (cmd *submitIgnoreRequest) createTheDeleteConfiguration(engine workflow.Engine, findingsId string, contentRoot types.FilePath) (configuration.Configuration, error) {
	if len(cmd.command.Arguments) < 3 {
		return nil, fmt.Errorf("insufficient arguments for ignore-delete workflow")
	}

	ignoreId, err := getIgnoreIdFromCmdArgs(cmd)
	if err != nil {
		return nil, err
	}

	gafConfig := createBaseConfiguration(engine, findingsId, contentRoot)
	gafConfig.Set(ignore_workflow.IgnoreIdKey, ignoreId)

	return gafConfig, nil
}

func createBaseConfiguration(engine workflow.Engine, findingId string, contentRoot types.FilePath) configuration.Configuration {
	gafConfig := engine.GetConfiguration().Clone()
	gafConfig.Set(ignore_workflow.FindingsIdKey, findingId) //TODO remove this one?
	gafConfig.Set(ignore_workflow.EnrichResponseKey, true)
	gafConfig.Set(ignore_workflow.InteractiveKey, false)
	gafConfig.Set(configuration.INPUT_DIRECTORY, contentRoot)
	return gafConfig
}

func addUpdateConfiguration(gafConfig configuration.Configuration, ignoreType string, reason string, expiration string) configuration.Configuration {
	gafConfig.Set(ignore_workflow.IgnoreTypeKey, ignoreType)
	gafConfig.Set(ignore_workflow.ReasonKey, reason)
	gafConfig.Set(ignore_workflow.ExpirationKey, expiration)
	return gafConfig
}

func updateIssueWithIgnoreDetails(c *config.Config, output []byte, issue types.Issue) error {
	var suppression sarif.Suppression
	err := json.Unmarshal(output, &suppression)
	if err != nil {
		return err
	}
	isIgnored, ignoreDetails := code.GetIgnoreDetailsFromSuppressions(c, []sarif.Suppression{suppression})

	issue.SetIgnored(isIgnored)
	issue.SetIgnoreDetails(ignoreDetails)
	return nil
}

func (cmd *submitIgnoreRequest) sendShowDocumentRequest(issue types.Issue) {
	snykUri, _ := code.SnykMagnetUri(issue, code.ShowInDetailPanelIdeCommand)
	logger := cmd.c.Logger()
	logger.Debug().
		Str("method", "code.sendShowDocumentRequest").
		Msg("showing Document")

	params := types.ShowDocumentParams{
		Uri:       lsp.DocumentURI(snykUri),
		Selection: converter.ToRange(issue.GetRange()),
	}
	_, err := cmd.srv.Callback(context.Background(), "window/showDocument", params)
	if err != nil {
		logger.Err(err).Msgf("failed to send snyk window/showDocument callback for file %s", issue.GetAffectedFilePath())
	}
}
