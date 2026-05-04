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

package server

import (
	"context"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/handler"

	"github.com/snyk/snyk-ls/domain/snyk"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

func textDocumentInlineValueHandler() jrpc2.Handler {
	return handler.New(func(ctx context.Context, params types.InlineValueParams) (any, error) {
		c := config.CurrentConfig()
		logger := c.Logger().With().Str("method", "textDocumentInlineValueHandler").Logger()
		documentURI := params.TextDocument.URI
		defer logger.Debug().Msgf("Request for %s:%s DONE", documentURI, params.Range.String())
		if s, ok := di.Scanner().(snyk.InlineValueProvider); ok {
			filePath := uri.PathFromUri(documentURI)
			values, err := s.GetInlineValues(filePath, converter.FromRange(params.Range))
			if err != nil {
				return nil, err
			}
			lspInlineValues := converter.ToInlineValues(values)
			logger.Trace().Msgf("found %d inline values for %s", len(values), filePath)
			return lspInlineValues, nil
		}
		return nil, nil
	})
}
