/*
 * © 2026 Snyk Limited
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
	"fmt"
	"html"
	"net/url"

	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/internal/types"
)

// showScanErrorDetails handles the snyk.showScanErrorDetails command.
// It receives a product name and error message from the tree view JS bridge,
// renders an error HTML page, and sends a window/showDocument callback with a
// snyk:// URI to trigger the IDE detail panel. The rendered HTML is also
// returned as the command result for clients that inspect the response.
type showScanErrorDetails struct {
	command types.CommandData
	srv     types.Server
}

func (cmd *showScanErrorDetails) Command() types.CommandData {
	return cmd.command
}

func (cmd *showScanErrorDetails) Execute(_ context.Context) (any, error) {
	args := cmd.command.Arguments
	if len(args) < 2 {
		return nil, fmt.Errorf("expected 2 arguments [product, errorMessage], got %d", len(args))
	}

	productName, _ := args[0].(string)
	errorMessage, _ := args[1].(string)

	if errorMessage == "" {
		return nil, fmt.Errorf("empty error message")
	}

	errorHtml := renderScanErrorHtml(productName, errorMessage)

	snykUri := fmt.Sprintf("snyk:///scan-error?product=%s&action=showScanError",
		url.QueryEscape(productName))
	params := types.ShowDocumentParams{
		Uri:       sglsp.DocumentURI(snykUri),
		External:  false,
		TakeFocus: false,
	}
	_, _ = cmd.srv.Callback(context.Background(), "window/showDocument", params)

	return errorHtml, nil
}

// renderScanErrorHtml generates a simple HTML page for displaying scan errors in the detail panel.
func renderScanErrorHtml(productName string, errorMessage string) string {
	escapedProduct := html.EscapeString(productName)
	escapedError := html.EscapeString(errorMessage)

	return fmt.Sprintf(`<html>
<head><meta charset="utf-8" /><style>
body { font-family: var(--vscode-font-family, sans-serif); font-size: var(--vscode-font-size, 13px); color: var(--vscode-foreground, #333); padding: 16px; }
h2 { color: var(--vscode-errorForeground, #f44747); margin-top: 0; }
.error-details { background: var(--vscode-textBlockQuote-background, #f5f5f5); border-left: 3px solid var(--vscode-errorForeground, #f44747); padding: 12px; margin: 12px 0; white-space: pre-wrap; word-break: break-word; }
</style></head>
<body>
<h2>Scan Failed — %s</h2>
<div class="error-details">%s</div>
</body>
</html>`, escapedProduct, escapedError)
}
