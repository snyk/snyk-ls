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

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
)

type trustWorkspaceFoldersCommand struct {
	command  types.CommandData
	notifier noti.Notifier
	c        *config.Config
}

func (cmd *trustWorkspaceFoldersCommand) Command() types.CommandData {
	return cmd.command
}

func (cmd *trustWorkspaceFoldersCommand) Execute(_ context.Context) (any, error) {
	if !cmd.c.IsTrustedFolderFeatureEnabled() {
		return nil, nil
	}

	_, untrusted := cmd.c.Workspace().GetFolderTrust()

	// Add trusted folders to config and send analytics
	workspace.SetTrustedFolders(cmd.c, untrusted)

	// Get the updated trusted folder paths for notification
	trustedFolderPaths := cmd.c.TrustedFolders()

	cmd.notifier.Send(types.SnykTrustedFoldersParams{TrustedFolders: trustedFolderPaths})
	return nil, nil
}
