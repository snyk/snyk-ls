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
	"github.com/snyk/snyk-ls/domain/ide"
	noti "github.com/snyk/snyk-ls/domain/ide/notification"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/lsp"
)

func CreateFromCommandData( //nolint:gocyclo // reasonable command dispatch
	commandData snyk.CommandData,
	srv lsp.Server,
	authService snyk.AuthenticationService,
	learnService learn.Service,
	notifier noti.Notifier,
	issueProvider ide.IssueProvider,
	codeApiClient SnykCodeHttpClient,
	codeScanner *code.Scanner,
) (snyk.Command, error) {
	httpClient := config.CurrentConfig().Engine().GetNetworkAccess().GetHttpClient

	switch commandData.CommandId {
	case snyk.NavigateToRangeCommand:
		return &navigateToRangeCommand{command: commandData, srv: srv}, nil
	case snyk.WorkspaceScanCommand:
		return &workspaceScanCommand{command: commandData, srv: srv}, nil
	case snyk.WorkspaceFolderScanCommand:
		return &workspaceFolderScanCommand{command: commandData, srv: srv}, nil
	case snyk.OpenBrowserCommand:
		return &openBrowserCommand{command: commandData}, nil
	case snyk.LoginCommand:
		return &loginCommand{command: commandData, authService: authService, notifier: notifier}, nil
	case snyk.CopyAuthLinkCommand:
		return &copyAuthLinkCommand{command: commandData, authService: authService, notifier: notifier}, nil
	case snyk.LogoutCommand:
		return &logoutCommand{command: commandData, authService: authService}, nil
	case snyk.TrustWorkspaceFoldersCommand:
		return &trustWorkspaceFoldersCommand{command: commandData, notifier: notifier}, nil
	case snyk.GetLearnLesson:
		return &getLearnLesson{command: commandData, srv: srv, learnService: learnService}, nil
	case snyk.OpenLearnLesson:
		return &openLearnLesson{command: commandData, srv: srv, learnService: learnService}, nil
	case snyk.GetSettingsSastEnabled:
		apiClient := snyk_api.NewSnykApiClient(httpClient)
		return &sastEnabled{command: commandData, apiClient: apiClient}, nil
	case snyk.GetFeatureFlagStatus:
		apiClient := snyk_api.NewSnykApiClient(httpClient)
		return &featureFlagStatus{command: commandData, apiClient: apiClient}, nil
	case snyk.GetActiveUserCommand:
		return &getActiveUser{command: commandData, authService: authService, notifier: notifier}, nil
	case snyk.ReportAnalyticsCommand:
		return &reportAnalyticsCommand{command: commandData}, nil
	case snyk.CodeFixCommand:
		return &fixCodeIssue{command: commandData, issueProvider: issueProvider, notifier: notifier}, nil
	case snyk.CodeSubmitFixFeedback:
		return &codeFixFeedback{command: commandData, apiClient: codeApiClient}, nil
	case snyk.CodeFixDiffsCommand:
		return &codeFixDiffs{
			command:       commandData,
			codeScanner:   codeScanner,
			issueProvider: issueProvider,
			notifier:      notifier,
		}, nil
	}

	return nil, fmt.Errorf("unknown command %v", commandData)
}
