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

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/lsp"
	"github.com/snyk/snyk-ls/internal/notification"
)

type trustWorkspaceFoldersCommand struct {
	command snyk.CommandData
}

func (cmd *trustWorkspaceFoldersCommand) Command() snyk.CommandData {
	return cmd.command
}

func (cmd *trustWorkspaceFoldersCommand) Execute(_ context.Context) (any, error) {
	if !config.CurrentConfig().IsTrustedFolderFeatureEnabled() {
		return nil, nil
	}

	trustedFolderPaths := config.CurrentConfig().TrustedFolders()
	_, untrusted := workspace.Get().GetFolderTrust()
	for _, folder := range untrusted {
		log.Debug().Str("method", "trustWorkspaceFoldersCommand").Msgf("adding trusted folder %s", folder.Path())
		trustedFolderPaths = append(trustedFolderPaths, folder.Path())
	}

	config.CurrentConfig().SetTrustedFolders(trustedFolderPaths)
	notification.Send(lsp.SnykTrustedFoldersParams{TrustedFolders: trustedFolderPaths})
	return nil, nil
}
