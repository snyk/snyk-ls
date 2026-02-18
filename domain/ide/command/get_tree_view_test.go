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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/ide/treeview"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestGetTreeViewCommand_Execute_ReturnsHtml(t *testing.T) {
	c := testutil.UnitTest(t)
	cmd := &getTreeViewCommand{
		command: types.CommandData{CommandId: types.GetTreeView},
		c:       c,
	}

	result, err := cmd.Execute(t.Context())
	require.NoError(t, err)

	htmlResult, ok := result.(string)
	require.True(t, ok, "result should be a string")
	assert.Contains(t, htmlResult, "<!DOCTYPE html>")
	assert.Contains(t, htmlResult, "${ideScript}")
}

func TestGetTreeViewCommand_Execute_WithScanStates_ShowsFileNodes(t *testing.T) {
	c := testutil.UnitTest(t)

	// Build tree data directly to verify the scan state path
	builder := treeview.NewTreeBuilder(treeview.GlobalExpandState())
	builder.SetProductScanStates(map[types.FilePath]map[product.Product]bool{
		"/project": {product.ProductCode: false},
	})

	data := builder.BuildTreeFromFolderData([]treeview.FolderData{{
		FolderPath:          "/project",
		FolderName:          "project",
		SupportedIssueTypes: map[product.FilterableIssueType]bool{product.FilterableIssueTypeCodeSecurity: true},
	}})

	renderer, err := treeview.NewTreeHtmlRenderer(c)
	require.NoError(t, err)
	html := renderer.RenderTreeView(data)

	assert.Contains(t, html, "Snyk Code", "expected Snyk Code product node")

	// Without scan states, builder would have empty children.
	// With scan states (scanRegistered=true, scanning=false), the product gets info children.
	assert.Contains(t, html, "No issues found", "completed scan with 0 issues should show info node")
}

func TestGetTreeViewCommand_Execute_WithScanStateFunc_CallsIt(t *testing.T) {
	c := testutil.UnitTest(t)

	called := false
	snapshot := scanstates.StateSnapshot{
		ProductScanStates: map[types.FilePath]map[product.Product]bool{
			"/project": {product.ProductCode: false},
		},
	}

	cmd := &getTreeViewCommand{
		command: types.CommandData{CommandId: types.GetTreeView},
		c:       c,
		scanStateFunc: func() scanstates.StateSnapshot {
			called = true
			return snapshot
		},
	}

	_, err := cmd.Execute(t.Context())
	require.NoError(t, err)
	assert.True(t, called, "scanStateFunc should be called during Execute")
}

func TestGetTreeViewCommand_Command_ReturnsCommandData(t *testing.T) {
	cmdData := types.CommandData{CommandId: types.GetTreeView}
	cmd := &getTreeViewCommand{
		command: cmdData,
	}

	assert.Equal(t, cmdData, cmd.Command())
}
