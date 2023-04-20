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
	"fmt"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/internal/lsp"
)

func CreateFromCommandData(
	commandData snyk.CommandData,
	srv lsp.Server,
	authService snyk.AuthenticationService,
	learnService learn.Service,
) (snyk.Command, error) {

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
		return &loginCommand{command: commandData, authService: authService}, nil
	case snyk.CopyAuthLinkCommand:
		return &copyAuthLinkCommand{command: commandData, authService: authService}, nil
	case snyk.LogoutCommand:
		return &logoutCommand{command: commandData, authService: authService}, nil
	case snyk.TrustWorkspaceFoldersCommand:
		return &trustWorkspaceFoldersCommand{command: commandData}, nil
	case snyk.OAuthRefreshCommand:
		return &oauthRefreshCommand{command: commandData, authService: authService}, nil
	case snyk.GetLearnLesson:
		return &getLearnLesson{command: commandData, srv: srv, learnService: learnService}, nil
	case snyk.OpenLearnLesson:
		return &openLearnLesson{command: commandData, srv: srv, learnService: learnService}, nil
	}

	return nil, fmt.Errorf("unknown command %v", commandData)
}
