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
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type mockWriter struct {
	written []byte
}

func (m *mockWriter) Write(p []byte) (n int, err error) {
	m.written = p
	return len(p), nil
}

func (m *mockWriter) WriteLevel(_ zerolog.Level, p []byte) (n int, err error) {
	m.written = p
	return len(p), nil
}

func TestScrubbingWriter_Write(t *testing.T) {
	scrubDict := map[string]bool{
		"password": true,
	}

	mockWriter := &mockWriter{}

	writer := NewScrubbingWriter(mockWriter, scrubDict)

	_, _ = writer.Write([]byte("password"))

	require.NotContainsf(t, mockWriter.written, "password", "password should be scrubbed")
}

func TestScrubbingWriter_WriteLevel(t *testing.T) {
	scrubDict := map[string]bool{
		"password": true,
	}

	mockWriter := &mockWriter{}

	writer := NewScrubbingWriter(mockWriter, scrubDict)

	_, _ = writer.WriteLevel(zerolog.InfoLevel, []byte("password"))

	require.NotContainsf(t, mockWriter.written, "password", "password should be scrubbed")
}
