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
	"os"
	"path/filepath"
	"testing"
	"time"

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

func Test_textDocumentInlineValues_shouldBeServed(t *testing.T) {
	c := testutil.UnitTest(t)
	loc, _ := setupServer(t, c)

	rsp, err := loc.Client.Call(ctx, "textDocument/inlineValue", nil)
	assert.NoError(t, err)

	var result []types.InlineValue
	err = rsp.UnmarshalResult(&result)
	assert.NoError(t, err)
}

func Test_textDocumentInlineValues_InlineValues_IntegTest(t *testing.T) {
	c := testutil.IntegTest(t)
	loc, _ := setupServer(t, c)
	di.Init()
	dir, err := filepath.Abs("testdata")
	assert.NoError(t, err)

	discovery := install.Discovery{}
	clientParams := types.InitializeParams{
		RootURI: uri.PathToUri(types.FilePath(dir)),
		InitializationOptions: types.Settings{
			ActivateSnykCode:            "false",
			ActivateSnykOpenSource:      "true",
			ActivateSnykIac:             "false",
			EnableTrustedFoldersFeature: "false",
			Token:                       os.Getenv("SNYK_TOKEN"),
			CliPath:                     filepath.Join(t.TempDir(), discovery.ExecutableName(false)),
		},
	}
	_, err = loc.Client.Call(ctx, "initialize", clientParams)
	assert.NoError(t, err)

	_, err = loc.Client.Call(ctx, "initialized", nil)
	assert.NoError(t, err)

	testFilePath := filepath.Join(dir, "package.json")
	documentURI := uri.PathToUri(types.FilePath(testFilePath))

	assert.Eventually(t, func() bool {
		// wait for scan
		rsp, err := loc.Client.Call(ctx, "textDocument/inlineValue", types.InlineValueParams{
			TextDocument: sglsp.TextDocumentIdentifier{URI: documentURI},
			Range:        sglsp.Range{Start: sglsp.Position{Line: 17}, End: sglsp.Position{Line: 17}},
		})
		assert.NoError(t, err)

		var inlineValues []types.InlineValue
		err = rsp.UnmarshalResult(&inlineValues)
		assert.NoError(t, err)

		return len(inlineValues) == 1 && inlineValues[0].Range.Start.Line == 17 && inlineValues[0].Range.End.Line == 17
	}, time.Minute, 1*time.Second, "expected inline values to be served, but they were not")
}
