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
	"strings"

	"github.com/sourcegraph/go-lsp"

	noti "github.com/snyk/snyk-ls/domain/ide/notification"
	"github.com/snyk/snyk-ls/domain/snyk"
)

// oauthRefreshCommand is a command that refreshes the oauth token
// This is needed because the token is only valid for a certain period of time
// For doing this we call the whoami workflow that will refresh the token automatically
type getActiveUser struct {
	command     snyk.CommandData
	authService snyk.AuthenticationService
	notifier    noti.Notifier
}

func (cmd *getActiveUser) Command() snyk.CommandData {
	return cmd.command
}

func (cmd *getActiveUser) Execute(ctx context.Context) (any, error) {
	user, err := snyk.GetActiveUser()
	if err != nil && strings.Contains(err.Error(), "400 Bad Request") {
		cmd.notifier.SendShowMessage(lsp.MTWarning, "Logging out automatically, available credentials are invalid. Please re-authenticate.")
		cmd.authService.Logout(ctx)
	}

	return user, err
}
