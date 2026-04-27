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

package testutil_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/testutil"
)

func decodeJWTPayload(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	require.Len(t, parts, 3, "JWT must have header.payload.signature shape")
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(payloadBytes, &payload))
	return payload
}

func TestBuildJWTWithAud_StringAud(t *testing.T) {
	jwt := testutil.BuildJWTWithAud(t, "api.eu.snyk.io")

	payload := decodeJWTPayload(t, jwt)
	assert.Equal(t, "api.eu.snyk.io", payload["aud"])
}

func TestBuildJWTWithAud_ArrayAud(t *testing.T) {
	jwt := testutil.BuildJWTWithAud(t, []string{"https://api.snyk.io", "https://other.snyk.io"})

	payload := decodeJWTPayload(t, jwt)
	auds, ok := payload["aud"].([]any)
	require.True(t, ok, "aud must be a JSON array, got %T", payload["aud"])
	require.Len(t, auds, 2)
	assert.Equal(t, "https://api.snyk.io", auds[0])
	assert.Equal(t, "https://other.snyk.io", auds[1])
}

func TestBuildJWTWithAud_NullAud(t *testing.T) {
	jwt := testutil.BuildJWTWithAud(t, nil)

	payload := decodeJWTPayload(t, jwt)
	require.Contains(t, payload, "aud")
	assert.Nil(t, payload["aud"], "nil aud must marshal to JSON null")
}

// recordingTB is a minimal testing.TB stub that records Fatalf invocations
// without aborting the parent test. Only the methods BuildJWTWithAud calls
// are implemented; everything else panics so accidental misuse is loud.
type recordingTB struct {
	testing.TB
	mu     sync.Mutex
	failed bool
	msg    string
}

func (r *recordingTB) Helper() {}

func (r *recordingTB) Fatalf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failed = true
	r.msg = format
}

// unmarshalable is a value json.Marshal rejects (chan types are not
// JSON-encodable).
type unmarshalable struct {
	C chan int
}

func TestBuildJWTWithAud_FatalOnUnmarshalable(t *testing.T) {
	rec := &recordingTB{}

	defer func() { _ = recover() }()
	_ = testutil.BuildJWTWithAud(rec, unmarshalable{C: make(chan int)})

	rec.mu.Lock()
	defer rec.mu.Unlock()
	assert.True(t, rec.failed, "BuildJWTWithAud must call Fatalf on json.Marshal failure")
	assert.Contains(t, rec.msg, "marshal", "Fatalf message should describe the marshal failure")
}
