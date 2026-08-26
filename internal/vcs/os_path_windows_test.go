//go:build windows

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

package vcs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOSPath(t *testing.T) {
	testCases := []struct {
		name string
		path string
		want string
	}{
		{
			name: "drive absolute gets the extended-length prefix",
			path: `C:\Users\dev\repo\prn.sh`,
			want: `\\?\C:\Users\dev\repo\prn.sh`,
		},
		{
			name: "UNC absolute gets the UNC extended form",
			path: `\\server\share\repo\nul.md`,
			want: `\\?\UNC\server\share\repo\nul.md`,
		},
		{
			name: "already prefixed is left alone",
			path: `\\?\C:\Users\dev\repo\con.go`,
			want: `\\?\C:\Users\dev\repo\con.go`,
		},
		{
			name: "already prefixed UNC is left alone",
			path: `\\?\UNC\server\share\repo\aux`,
			want: `\\?\UNC\server\share\repo\aux`,
		},
		{
			name: "relative is left alone, an extended path must be absolute",
			path: `repo\lpt9.js`,
			want: `repo\lpt9.js`,
		},
		{
			name: "drive relative is left alone, it is not absolute",
			path: `C:repo\com1.txt`,
			want: `C:repo\com1.txt`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, OSPath(tc.path))
		})
	}
}

// TestOSPath_ReachesAReservedDeviceName is the claim the whole Windows path
// rests on: the returned form addresses a real file rather than the device.
func TestOSPath_ReachesAReservedDeviceName(t *testing.T) {
	target := filepath.Join(t.TempDir(), "prn.sh")

	require.NoError(t, os.WriteFile(OSPath(target), []byte("content"), 0600))

	content, err := os.ReadFile(OSPath(target))
	require.NoError(t, err)
	assert.Equal(t, "content", string(content))
}
