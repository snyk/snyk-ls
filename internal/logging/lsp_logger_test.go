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

package logging

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/types"
)

// stubServer is a minimal Server implementation for testing.
type stubServer struct {
	notifyCount atomic.Int64
	blockCh     chan struct{} // when non-nil, Notify blocks until closed
}

func (s *stubServer) Notify(_ context.Context, _ string, _ any) error {
	if s.blockCh != nil {
		<-s.blockCh
	}
	s.notifyCount.Add(1)
	return nil
}

func (s *stubServer) Callback(_ context.Context, _ string, _ any) (*jrpc2.Response, error) {
	return nil, nil
}

func TestWriteLevel(t *testing.T) {
	tests := []struct {
		name            string
		level           zerolog.Level
		expectForwarded bool
	}{
		{
			name:            "error level is forwarded",
			level:           zerolog.ErrorLevel,
			expectForwarded: true,
		},
		{
			name:            "warn level is forwarded",
			level:           zerolog.WarnLevel,
			expectForwarded: true,
		},
		{
			name:            "info level is forwarded",
			level:           zerolog.InfoLevel,
			expectForwarded: true,
		},
		{
			name:            "debug level is forwarded",
			level:           zerolog.DebugLevel,
			expectForwarded: true,
		},
		{
			name:            "trace level is filtered out",
			level:           zerolog.TraceLevel,
			expectForwarded: false,
		},
		{
			name:            "no level is filtered out",
			level:           zerolog.NoLevel,
			expectForwarded: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := &stubServer{}
			w := New(srv).(*lspWriter)

			n, err := w.WriteLevel(tc.level, []byte("test message"))
			assert.NoError(t, err)

			if tc.expectForwarded {
				assert.Equal(t, len("test message"), n)
				assert.Eventually(t, func() bool {
					return srv.notifyCount.Load() == 1
				}, 2*time.Second, 10*time.Millisecond)
			} else {
				// Give a short window to confirm nothing was sent
				time.Sleep(50 * time.Millisecond)
				assert.Equal(t, int64(0), srv.notifyCount.Load())
			}
		})
	}
}

func TestWriteLevel_NonBlockingWhenChannelFull(t *testing.T) {
	srv := &stubServer{blockCh: make(chan struct{})}

	// Create writer with a tiny channel so we can fill it easily
	readyChan := make(chan bool)
	writeChan := make(chan types.LogMessageParams, 2)
	w := &lspWriter{
		writeChan: writeChan,
		readyChan: readyChan,
		server:    srv,
	}
	go w.startServerSenderRoutine()
	<-readyChan

	// Fill the channel (server blocks so nothing drains)
	_, _ = w.WriteLevel(zerolog.InfoLevel, []byte("msg1"))
	_, _ = w.WriteLevel(zerolog.InfoLevel, []byte("msg2"))

	// This third write must not block — it should fall through to stderr
	done := make(chan struct{})
	go func() {
		_, _ = w.WriteLevel(zerolog.InfoLevel, []byte("msg3-dropped"))
		close(done)
	}()

	select {
	case <-done:
		// success: WriteLevel returned without blocking
	case <-time.After(2 * time.Second):
		t.Fatal("WriteLevel blocked when channel was full — expected non-blocking fallback to stderr")
	}

	// Unblock the server so the goroutine can drain
	close(srv.blockCh)
}
