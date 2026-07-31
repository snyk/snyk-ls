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
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_GetIssueKey(t *testing.T) {
	id := GetIssueKey("java/DontUsePrintStackTrace", "file/path.java", 15, 17, 15, 35)
	assert.Equal(t, "8423559307c17d15f5617ae2e29dbf02", id)
}

// UNIT-001: same inputs always yield the same hex digest, and that digest is a
// fixed golden value. The golden assertion locks the exact NUL-delimited preimage
// formula (Fix 4) so any accidental change to the wire identity is caught.
func TestComputeFindingIdentity_Deterministic(t *testing.T) {
	id1 := ComputeFindingIdentity("rule/XSS", "src/main.go", 5, 2, 5, 20)
	id2 := ComputeFindingIdentity("rule/XSS", "src/main.go", 5, 2, 5, 20)

	assert.NotEmpty(t, id1, "identity must not be empty")
	assert.Equal(t, id1, id2, "same inputs must produce identical identity")
	// Golden value. Reproducible preimage: the fields below joined by a NUL byte
	// (shown here as \x00), then SHA-256, then the first 16 bytes hex-encoded:
	//   "rule/XSS\x00src/main.go\x005\x002\x005\x0020"
	// i.e. groupingKey \x00 rootRelPath \x00 startLine \x00 startCol \x00 endLine \x00 endCol.
	// A human can verify with:
	//   printf 'rule/XSS\x00src/main.go\x005\x002\x005\x0020' | sha256sum | cut -c1-32
	assert.Equal(t, "b34b8ec7d659575b7917ca60f1bbaee9", id1,
		"identity formula must remain stable; a change here changes the wire FindingId for every finding")
}

// Fix 4: the preimage must be delimited so that two distinct field tuples cannot
// map to the same byte sequence. With a space delimiter, ("a b", "c") and
// ("a", "b c") both produce "a b c ..." and collide. A NUL separator keeps them
// distinct.
func TestComputeFindingIdentity_FieldDelimiterNoCollision(t *testing.T) {
	id1 := ComputeFindingIdentity("a b", "c", 0, 0, 0, 0)
	id2 := ComputeFindingIdentity("a", "b c", 0, 0, 0, 0)

	assert.NotEqual(t, id1, id2,
		"distinct (groupingKey, rootRelPath) tuples must not share a preimage")
}

// UNIT-002: same groupingKey and path but different ranges produce different identities,
// ensuring two findings at distinct locations individuate even when they share a rule.
func TestComputeFindingIdentity_InstanceUnique(t *testing.T) {
	id1 := ComputeFindingIdentity("rule/SQLi", "db/query.go", 3, 0, 3, 10)
	id2 := ComputeFindingIdentity("rule/SQLi", "db/query.go", 7, 0, 7, 10)

	assert.NotEqual(t, id1, id2, "different ranges must produce different identities")
}

// UNIT-003: a root-relative path and an absolute path for the same file produce different
// outputs, demonstrating that callers must normalise to root-relative before calling.
// Worktree portability comes from the CALLER computing the same root-relative string
// regardless of where the tree is mounted.
func TestComputeFindingIdentity_RootRelative(t *testing.T) {
	// Root-relative path – the correct input for a portable identity.
	relId := ComputeFindingIdentity("rule/SSRF", "pkg/server.go", 1, 0, 1, 5)
	// Absolute path – what a caller would pass without root-relative normalisation.
	absId := ComputeFindingIdentity("rule/SSRF", "/project/pkg/server.go", 1, 0, 1, 5)

	assert.NotEmpty(t, relId)
	assert.NotEmpty(t, absId)
	assert.NotEqual(t, relId, absId,
		"root-relative and absolute paths must produce different identities; worktree portability requires the caller to pass the root-relative path consistently")

	// Verify determinism: the same relative path always gives the same id (worktree invariant).
	relId2 := ComputeFindingIdentity("rule/SSRF", "pkg/server.go", 1, 0, 1, 5)
	assert.Equal(t, relId, relId2, "same root-relative input must always produce the same identity")
}
