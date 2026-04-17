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

package testsupport

import (
	"testing"

	"github.com/creachadair/jrpc2"
	"github.com/stretchr/testify/require"
)

func parseOneRequest(t *testing.T, msg []byte) jrpc2.Request {
	t.Helper()
	parsed, err := jrpc2.ParseRequests(msg)
	require.NoError(t, err)
	require.Len(t, parsed, 1)
	require.Nil(t, parsed[0].Error, "fixture must be valid JSON-RPC: %v", parsed[0].Error)
	req := parsed[0].ToRequest()
	require.NotNil(t, req)
	return *req
}

func TestJsonRPCRecorder_DrainRecordedTrafficForProfiling_clears_notifications_and_callbacks(t *testing.T) {
	var r JsonRPCRecorder
	// ParseRequests fixtures with an "id" field are classified as callbacks by Record.
	// DrainRecordedTrafficForProfiling clears both notifications and callbacks (megaproject heap).
	n := parseOneRequest(t, []byte(`{"jsonrpc":"2.0","method":"textDocument/publishDiagnostics","id":0,"params":{}}`))
	c := parseOneRequest(t, []byte(`{"jsonrpc":"2.0","method":"window/showMessageRequest","id":1,"params":{}}`))
	r.Record(n)
	r.Record(c)
	require.Len(t, r.Callbacks(), 2)

	// A zero jrpc2.Request is a notification (nil id); the smoke server records real notifications
	// this way. Same-package test reaches the notifications slice directly.
	r.mutex.Lock()
	r.notifications = append(r.notifications, jrpc2.Request{})
	r.mutex.Unlock()
	require.Len(t, r.Notifications(), 1)

	r.DrainRecordedTrafficForProfiling()

	require.Empty(t, r.Notifications())
	require.Empty(t, r.Callbacks())
	require.Empty(t, r.FindCallbacksByMethod("textDocument/publishDiagnostics"))
	require.Empty(t, r.FindCallbacksByMethod("window/showMessageRequest"))
}

func TestJsonRPCRecorder_DrainRecordedTrafficForProfiling_idempotent(t *testing.T) {
	var r JsonRPCRecorder
	r.DrainRecordedTrafficForProfiling()
	r.DrainRecordedTrafficForProfiling()
	require.Empty(t, r.Notifications())
	require.Empty(t, r.Callbacks())
}

func TestJsonRPCRecorder_record_and_find_roundtrip_before_drain(t *testing.T) {
	var r JsonRPCRecorder
	req := parseOneRequest(t, []byte(`{"jsonrpc":"2.0","method":"$/snyk.scan","id":99,"params":{"folder":"x"}}`))
	r.Record(req)
	found := r.FindCallbacksByMethod("$/snyk.scan")
	require.Len(t, found, 1)
	r.DrainRecordedTrafficForProfiling()
	require.Empty(t, r.FindCallbacksByMethod("$/snyk.scan"))
}
