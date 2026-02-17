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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/types"
)

func TestShowScanErrorDetails_ReturnsErrorHtml(t *testing.T) {
	cmd := &showScanErrorDetails{
		command: types.CommandData{
			CommandId: types.ShowScanErrorDetails,
			Arguments: []any{"Snyk Open Source", "dependency graph failed"},
		},
	}

	result, err := cmd.Execute(context.Background())
	require.NoError(t, err)

	html, ok := result.(string)
	require.True(t, ok, "result should be a string")
	assert.Contains(t, html, "Scan Failed")
	assert.Contains(t, html, "Snyk Open Source")
	assert.Contains(t, html, "dependency graph failed")
}

func TestShowScanErrorDetails_MissingArgs_ReturnsError(t *testing.T) {
	cmd := &showScanErrorDetails{
		command: types.CommandData{
			CommandId: types.ShowScanErrorDetails,
			Arguments: []any{"product"},
		},
	}

	_, err := cmd.Execute(context.Background())
	assert.Error(t, err)
}

func TestShowScanErrorDetails_EmptyErrorMessage_ReturnsError(t *testing.T) {
	cmd := &showScanErrorDetails{
		command: types.CommandData{
			CommandId: types.ShowScanErrorDetails,
			Arguments: []any{"Snyk Code", ""},
		},
	}

	_, err := cmd.Execute(context.Background())
	assert.Error(t, err)
}

func TestRenderScanErrorHtml_EscapesHtmlEntities(t *testing.T) {
	html := renderScanErrorHtml("Test <Product>", "error with <script>alert('xss')</script>")
	assert.Contains(t, html, "Test &lt;Product&gt;")
	assert.Contains(t, html, "&lt;script&gt;")
	assert.NotContains(t, html, "<script>alert")
}
