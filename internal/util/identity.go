/*
 * © 2024 Snyk Limited
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

package util

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

// GetIssueKey returns the per-result-set key for an issue.
//
// WARNING: the coordinate parameter order here is (startLine, endLine, startCol,
// endCol) — lines first, then columns. This DIFFERS from
// ComputeFindingIdentity, whose order is (startLine, startCol, endLine, endCol).
// The two are not interchangeable; transposing them silently produces a wrong,
// still-valid-looking hex id. Match the parameter names, not the position, when
// calling either function.
func GetIssueKey(ruleId string, path string, startLine int, endLine int, startCol int, endCol int) string {
	id := sha256.Sum256([]byte(ruleId + path + strconv.Itoa(startLine) + strconv.Itoa(endLine) + strconv.Itoa(startCol) + strconv.Itoa(endCol)))
	return hex.EncodeToString(id[:16])
}

// ComputeFindingIdentity returns a deterministic, hex-truncated identity for a
// finding that is stable across scans, unique per instance, and portable across
// a git-worktree copy of the same tree.
//
//   - groupingKey is the product's durable grouping key (what makes two
//     observations "the same finding"); the range discriminates two findings
//     that share a grouping key at different locations.
//   - rootRelPath must be the affected file path expressed relative to the
//     finding's workspace root, with forward slashes. Passing the root-relative
//     path is what makes the identity identical in the working tree and in a
//     worktree copy; passing an absolute path yields a machine-specific,
//     non-portable identity.
//
// Range coordinates are taken as plain ints so this package does not depend on
// internal/types (which itself depends on internal/util).
func ComputeFindingIdentity(groupingKey string, rootRelPath string, startLine int, startCol int, endLine int, endCol int) string {
	// Fields are separated by a NUL byte, which cannot appear in a grouping key
	// or a file path, so the preimage is unambiguous. A printable delimiter (e.g.
	// a space) would let ("a b", "c") and ("a", "b c") collide onto the same
	// preimage.
	const sep = "\x00"
	id := sha256.Sum256([]byte(groupingKey + sep + rootRelPath + sep +
		strconv.Itoa(startLine) + sep + strconv.Itoa(startCol) + sep +
		strconv.Itoa(endLine) + sep + strconv.Itoa(endCol)))
	return hex.EncodeToString(id[:16])
}
