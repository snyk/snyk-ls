/*
 * © 2023-2024 Snyk Limited
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
	"fmt"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/treeview"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
)

// CreateFromCommandData gets a command based on the given parameters that can be passed to the CommandService
// nolint: gocyclo, nolintlint // this is a factory, it's ok to have high cyclomatic complexity here
func CreateFromCommandData(
	c *config.Config,
	commandData types.CommandData,
	srv types.Server,
	authService authentication.AuthenticationService,
	featureFlagService featureflag.Service,
	learnService learn.Service,
	notifier noti.Notifier,
	issueProvider snyk.IssueProvider,
	codeScanner *code.Scanner,
	cli cli.Executor,
	ldxSyncService LdxSyncService,
	configResolver types.ConfigResolverInterface,
) (types.Command, error) {
	snykApiClient := snyk_api.NewSnykApiClient(c, c.Engine().GetNetworkAccess().GetHttpClient)

	switch commandData.CommandId {
	case types.NavigateToRangeCommand:
		return &navigateToRangeCommand{
			command:            commandData,
			srv:                srv,
			logger:             c.Logger(),
			c:                  c,
			featureFlagService: featureFlagService,
		}, nil
	case types.WorkspaceScanCommand:
		return &workspaceScanCommand{command: commandData, srv: srv, c: c}, nil
	case types.WorkspaceFolderScanCommand:
		return &workspaceFolderScanCommand{command: commandData, srv: srv, c: c}, nil
	case types.OpenBrowserCommand:
		return &openBrowserCommand{command: commandData, logger: c.Logger()}, nil
	case types.LoginCommand:
		return &loginCommand{command: commandData, authService: authService, notifier: notifier, c: c, featureFlagService: featureFlagService, ldxSyncService: ldxSyncService, configResolver: configResolver}, nil
	case types.CopyAuthLinkCommand:
		return &copyAuthLinkCommand{command: commandData, authService: authService, notifier: notifier, logger: c.Logger()}, nil
	case types.LogoutCommand:
		return &logoutCommand{command: commandData, authService: authService, c: c, featureFlagService: featureFlagService}, nil
	case types.TrustWorkspaceFoldersCommand:
		return &trustWorkspaceFoldersCommand{command: commandData, notifier: notifier, c: c}, nil
	case types.GetLearnLesson:
		return &getLearnLesson{command: commandData, srv: srv, learnService: learnService}, nil
	case types.OpenLearnLesson:
		return &openLearnLesson{command: commandData, srv: srv, learnService: learnService}, nil
	case types.GetSettingsSastEnabled:
		return &sastEnabled{command: commandData, logger: c.Logger(), authenticationService: authService, gafConfig: c.Engine().GetConfiguration()}, nil
	case types.GetFeatureFlagStatus:
		return &featureFlagStatus{command: commandData, apiClient: snykApiClient, authenticationService: authService}, nil
	case types.GetActiveUserCommand:
		return &getActiveUser{command: commandData, authenticationService: authService, notifier: notifier}, nil
	case types.ReportAnalyticsCommand:
		return &reportAnalyticsCommand{command: commandData, authenticationService: authService}, nil
	case types.CodeFixCommand:
		return &fixCodeIssue{command: commandData, issueProvider: issueProvider, notifier: notifier, logger: c.Logger()}, nil
	case types.CodeFixApplyEditCommand:
		return &applyAiFixEditCommand{
			command:            commandData,
			issueProvider:      issueProvider,
			notifier:           notifier,
			c:                  c,
			logger:             c.Logger(),
			featureFlagService: featureFlagService,
		}, nil
	case types.CodeSubmitFixFeedback:
		return &codeFixFeedback{command: commandData}, nil
	case types.CodeFixDiffsCommand:
		return &codeFixDiffs{
			command:            commandData,
			codeScanner:        codeScanner,
			srv:                srv,
			issueProvider:      issueProvider,
			notifier:           notifier,
			c:                  c,
			featureFlagService: featureFlagService,
		}, nil
	case types.ExecuteCLICommand:
		return &executeCLICommand{command: commandData, authService: authService, notifier: notifier, logger: c.Logger(), cli: cli}, nil
	case types.ClearCacheCommand:
		return &clearCache{command: commandData, c: c}, nil
	case types.GenerateIssueDescriptionCommand:
		return &generateIssueDescription{
			command:            commandData,
			issueProvider:      issueProvider,
			featureFlagService: featureFlagService,
		}, nil
	case types.SubmitIgnoreRequest:
		return &submitIgnoreRequest{command: commandData, issueProvider: issueProvider, notifier: notifier, srv: srv, c: c}, nil
	case types.WorkspaceConfigurationCommand:
		return &configurationCommand{command: commandData, srv: srv, logger: c.Logger(), c: c, configResolver: configResolver}, nil
	case types.GetTreeView:
		return &getTreeViewCommand{command: commandData, c: c}, nil
	case types.GetTreeViewIssueChunk:
		return &getTreeViewIssueChunk{command: commandData, c: c}, nil
	case types.ToggleTreeFilter:
		return &toggleTreeFilter{command: commandData, c: c}, nil
	case types.SetNodeExpanded:
		return &setNodeExpanded{command: commandData, expandState: treeview.GlobalExpandState()}, nil
	}

	return nil, fmt.Errorf("unknown command %v", commandData)
}
