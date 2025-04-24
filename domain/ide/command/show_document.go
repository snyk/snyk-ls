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

	"github.com/rs/zerolog"
	"github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/internal/types"
)

func SendShowDocumentRequest(ctx context.Context, logger zerolog.Logger, issue types.Issue, srv types.Server) {
	snykUri, _ := code.SnykMagnetUri(issue, code.ShowInDetailPanelIdeCommand)
	logger.Debug().
		Str("method", "code.sendShowDocumentRequest").
		Msg("showing Document")

	params := types.ShowDocumentParams{
		Uri:       lsp.DocumentURI(snykUri),
		Selection: converter.ToRange(issue.GetRange()),
	}
	_, err := srv.Callback(ctx, "window/showDocument", params)
	if err != nil {
		logger.Err(err).Msgf("failed to send snyk window/showDocument callback for file %s", issue.GetAffectedFilePath())
	}
}
