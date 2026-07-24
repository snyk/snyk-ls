/*
 * © 2025 Snyk Limited
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

package snyk

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIssue_SetFindingId_NoDataRace (T4)
//
// Exercises concurrent SetFindingId + GetFindingId on a single *Issue.
//
// RED before fix: SetFindingId uses i.m.RLock() around a write to i.FindingId.
// sync.RWMutex allows multiple concurrent RLock holders, so N goroutines calling
// SetFindingId simultaneously race on i.FindingId with no mutual exclusion.
// `go test -race ./domain/snyk/` reports a data race.
//
// GREEN after fix: SetFindingId uses i.m.Lock()/Unlock() (write lock), matching
// the pattern of all other Set* methods (e.g. SetIgnored).
func TestIssue_SetFindingId_NoDataRace(t *testing.T) {
	const writers = 10
	const readers = 10

	issue := &Issue{}

	var wg sync.WaitGroup
	wg.Add(writers + readers)

	// N concurrent writers
	for i := range writers {
		go func(n int) {
			defer wg.Done()
			issue.SetFindingId(fmt.Sprintf("finding-%d", n))
		}(i)
	}

	// M concurrent readers — race detector catches a write racing with a read
	// even if the read is under RLock and the write is also under RLock.
	for range readers {
		go func() {
			defer wg.Done()
			_ = issue.GetFindingId()
		}()
	}

	wg.Wait()

	// After all goroutines finish, FindingId must be one of the written values
	// (or the empty initial value if no writer landed).
	id := issue.GetFindingId()
	valid := id == ""
	for i := range writers {
		if id == fmt.Sprintf("finding-%d", i) {
			valid = true
			break
		}
	}
	assert.True(t, valid, "FindingId %q must be one of the values written by the goroutines", id)
}
