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

package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestGetCodeActionHandler_NilService_ReturnsNilAndNoError(t *testing.T) {
	// When svc is nil (programming error — service not wired at startup), the handler
	// must log a warning and return nil, nil rather than panicking.
	engine := testutil.UnitTest(t)
	logger := engine.GetLogger()
	handler := GetCodeActionHandler(logger, nil)
	require.NotNil(t, handler, "handler closure must always be returned even for nil svc")

	actions, err := handler(t.Context(), types.CodeActionParams{})
	assert.Nil(t, actions)
	assert.NoError(t, err)
}
