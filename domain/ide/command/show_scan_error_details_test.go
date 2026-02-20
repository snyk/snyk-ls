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
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

func TestShowScanErrorDetails_ReturnsErrorHtml(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSrv := mock_types.NewMockServer(ctrl)

	mockSrv.EXPECT().Callback(gomock.Any(), "window/showDocument", gomock.Any()).DoAndReturn(
		func(_ context.Context, _ string, params any) (any, error) {
			return nil, nil
		}).Times(1)

	cmd := &showScanErrorDetails{
		command: types.CommandData{
			CommandId: types.ShowScanErrorDetails,
			Arguments: []any{"Snyk Open Source", "dependency graph failed"},
		},
		srv: mockSrv,
	}

	result, err := cmd.Execute(context.Background())
	require.NoError(t, err)

	html, ok := result.(string)
	require.True(t, ok, "result should be a string")
	assert.Contains(t, html, "Scan Failed")
	assert.Contains(t, html, "Snyk Open Source")
	assert.Contains(t, html, "dependency graph failed")
}

func TestShowScanErrorDetails_CallsShowDocumentWithSnykUri(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSrv := mock_types.NewMockServer(ctrl)

	var capturedParams types.ShowDocumentParams
	mockSrv.EXPECT().Callback(gomock.Any(), "window/showDocument", gomock.Any()).DoAndReturn(
		func(_ context.Context, _ string, params any) (any, error) {
			capturedParams = params.(types.ShowDocumentParams)
			return nil, nil
		}).Times(1)

	cmd := &showScanErrorDetails{
		command: types.CommandData{
			CommandId: types.ShowScanErrorDetails,
			Arguments: []any{"Snyk Open Source", "dependency graph failed"},
		},
		srv: mockSrv,
	}

	_, err := cmd.Execute(context.Background())
	require.NoError(t, err)

	uri := string(capturedParams.Uri)
	assert.Contains(t, uri, "snyk://")
	assert.Contains(t, uri, "action=showScanError")
	assert.Contains(t, uri, "product=Snyk+Open+Source")
	assert.False(t, capturedParams.External)
	assert.False(t, capturedParams.TakeFocus)
}

func TestShowScanErrorDetails_MissingArgs_ReturnsError(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSrv := mock_types.NewMockServer(ctrl)

	cmd := &showScanErrorDetails{
		command: types.CommandData{
			CommandId: types.ShowScanErrorDetails,
			Arguments: []any{"product"},
		},
		srv: mockSrv,
	}

	_, err := cmd.Execute(context.Background())
	assert.Error(t, err)
}

func TestShowScanErrorDetails_EmptyErrorMessage_ReturnsError(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSrv := mock_types.NewMockServer(ctrl)

	cmd := &showScanErrorDetails{
		command: types.CommandData{
			CommandId: types.ShowScanErrorDetails,
			Arguments: []any{"Snyk Code", ""},
		},
		srv: mockSrv,
	}

	_, err := cmd.Execute(context.Background())
	assert.Error(t, err)
}

func TestShowScanErrorDetails_CallbackError_StillReturnsHtml(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSrv := mock_types.NewMockServer(ctrl)

	mockSrv.EXPECT().Callback(gomock.Any(), "window/showDocument", gomock.Any()).
		Return(nil, fmt.Errorf("IDE rejected showDocument")).Times(1)

	cmd := &showScanErrorDetails{
		command: types.CommandData{
			CommandId: types.ShowScanErrorDetails,
			Arguments: []any{"Snyk Code", "analysis timed out"},
		},
		srv: mockSrv,
	}

	result, err := cmd.Execute(context.Background())
	require.NoError(t, err, "callback failure should not propagate as command error")

	html, ok := result.(string)
	require.True(t, ok, "result should still be a string")
	assert.Contains(t, html, "analysis timed out")
}

func TestRenderScanErrorHtml_EscapesHtmlEntities(t *testing.T) {
	html := renderScanErrorHtml("Test <Product>", "error with <script>alert('xss')</script>")
	assert.Contains(t, html, "Test &lt;Product&gt;")
	assert.Contains(t, html, "&lt;script&gt;")
	assert.NotContains(t, html, "<script>alert")
}
