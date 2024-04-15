/*
 * © 2022-2024 Snyk Limited
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

package snyk

import (
	"context"
	"sync"

	"github.com/snyk/go-application-framework/pkg/auth"

	"github.com/snyk/snyk-ls/internal/lsp"
)

const (
	NavigateToRangeCommand       = "snyk.navigateToRange"
	WorkspaceScanCommand         = "snyk.workspace.scan"
	WorkspaceFolderScanCommand   = "snyk.workspaceFolder.scan"
	OpenBrowserCommand           = "snyk.openBrowser"
	LoginCommand                 = "snyk.login"
	CopyAuthLinkCommand          = "snyk.copyAuthLink"
	LogoutCommand                = "snyk.logout"
	TrustWorkspaceFoldersCommand = "snyk.trustWorkspaceFolders"
	OpenLearnLesson              = "snyk.openLearnLesson"
	GetLearnLesson               = "snyk.getLearnLesson"
	GetSettingsSastEnabled       = "snyk.getSettingsSastEnabled"
	GetFeatureFlagStatus         = "snyk.getFeatureFlagStatus"
	GetActiveUserCommand         = "snyk.getActiveUser"
	ReportAnalyticsCommand       = "snyk.reportAnalytics"

	// Snyk Code specific commands
	CodeFixCommand        = "snyk.code.fix"
	CodeSubmitFixFeedback = "snyk.code.submitFixFeedback"
	CodeFixDiffsCommand   = "snyk.code.fixDiffs"
)

var (
	DefaultOpenBrowserFunc = func(url string) { auth.OpenBrowser(url) }
)

type Command interface {
	Command() CommandData
	Execute(ctx context.Context) (any, error)
}

type CommandData struct {
	/**
	 * Title of the command, like `save`.
	 */
	Title string
	/**
	 * The identifier of the actual command handler.
	 */
	CommandId string
	/**
	 * Arguments that the command handler should be
	 * invoked with.
	 */
	Arguments []any
}

type CommandName string

type CommandService interface {
	ExecuteCommandData(ctx context.Context, commandData CommandData, server lsp.Server) (any, error)
}

type CommandServiceMock struct {
	m                sync.Mutex
	executedCommands []CommandData
}

func NewCommandServiceMock() *CommandServiceMock {
	return &CommandServiceMock{}
}

func (service *CommandServiceMock) ExecuteCommandData(_ context.Context, command CommandData, server lsp.Server) (any, error) {
	service.m.Lock()
	service.executedCommands = append(service.executedCommands, command)
	service.m.Unlock()
	return nil, nil
}

func (service *CommandServiceMock) ExecutedCommands() []CommandData {
	service.m.Lock()
	cmds := service.executedCommands
	service.m.Unlock()
	return cmds
}
