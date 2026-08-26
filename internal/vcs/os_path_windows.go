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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const extendedLengthPrefix = `\\?\`

// OSPath returns p in extended-length form, which skips Win32 path parsing and
// with it the interception of reserved device names such as prn.sh. Extended
// paths get no normalization, so p must already be absolute and cleaned;
// anything else is returned unchanged rather than silently mangled. Exported
// because callers outside this package need it to stat or read what we wrote.
func OSPath(p string) string {
	if strings.HasPrefix(p, extendedLengthPrefix) || !filepath.IsAbs(p) {
		return p
	}
	if strings.HasPrefix(p, `\\`) {
		return extendedLengthPrefix + `UNC` + strings.TrimPrefix(p, `\`)
	}
	return extendedLengthPrefix + p
}

// isSymlinkPrivilegeError reports the one failure git itself tolerates: an
// unprivileged Windows process cannot create symlinks at all.
func isSymlinkPrivilegeError(err error) bool {
	const errorPrivilegeNotHeld syscall.Errno = 1314

	var linkErr *os.LinkError
	if !errors.As(err, &linkErr) {
		return false
	}
	var errno syscall.Errno
	return errors.As(linkErr.Err, &errno) && errno == errorPrivilegeNotHeld
}
