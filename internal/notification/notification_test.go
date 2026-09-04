/*
 * © 2022 Snyk Limited All rights reserved.
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

package notification

import (
	"encoding/json"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/concurrency"
	"github.com/snyk/snyk-ls/internal/types"
)

var params = types.AuthenticationParams{Token: "test event", ApiUrl: "https://api.snyk.io"}

func TestSendReceive(t *testing.T) {
	n := NewNotifier()
	n.Send(params)
	output, _ := n.Receive()
	assert.Equal(t, params, output)
}

// Asserted on the marshaled payload: the client reads the href off the wire, and
// a Go field holding a valid URL proves nothing about what is serialized.
func TestSendErrorDiagnostic(t *testing.T) {
	n := NewNotifier()
	go n.SendErrorDiagnostic("/repo/file.go", errors.New("scan failed"))

	output, _ := n.Receive()

	diagnosticParams, ok := output.(types.PublishDiagnosticsParams)
	require.True(t, ok)
	require.Len(t, diagnosticParams.Diagnostics, 1)

	payload, err := json.Marshal(diagnosticParams.Diagnostics[0])
	require.NoError(t, err)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(payload, &decoded))

	assert.Equal(t, "scan failed", decoded["message"])
	codeDescription, ok := decoded["codeDescription"].(map[string]any)
	require.True(t, ok, "an error diagnostic links to the user hub: %s", payload)

	href, ok := codeDescription["href"].(string)
	require.True(t, ok)
	parsedHref, err := url.Parse(href)
	require.NoError(t, err)
	assert.Equal(t, "https", parsedHref.Scheme,
		"a relative or non-web href is resolved against the workspace, so the client opens a non-existent file")
	assert.Equal(t, "https://snyk.io/user-hub", href)
}

func TestCreateListener(t *testing.T) {
	called := concurrency.AtomicBool{}
	n := NewNotifier()
	n.CreateListener(func(event any) {
		called.Set(true)
	})
	defer n.DisposeListener()
	n.Send(params)
	assert.Eventually(t, func() bool {
		return called.Get()
	}, 2*time.Second, time.Second)
}
