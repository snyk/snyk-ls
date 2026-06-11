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

package code

import (
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

var testProgressChannels = make(chan types.ProgressParams, 10000)
var testCancelProgressChannel = make(chan bool, 10000)

func Test_Tracker_Begin(t *testing.T) {
	testutil.UnitTest(t)
	tracker := newCodeTracker(testProgressChannels, testCancelProgressChannel)
	tracker.Begin("title", "message")

	hasBegun := false
	assert.Eventually(
		t,
		func() bool {
			for {
				select {
				case p := <-testProgressChannels:
					if p.Value == nil {
						hasBegun = true
						return false
					} else {
						switch value := p.Value.(type) {
						case types.WorkDoneProgressBegin:
							if !hasBegun {
								return false
							}
							return value.Title == "title" && value.Message == "message"
						case types.WorkDoneProgressEnd:
							return false
						}
					}
				default:
				}
				break //nolint:staticcheck // unconditional termination is intentional — poll once per Eventually tick
			}
			return false
		},
		5*time.Second,
		10*time.Millisecond,
	)
}
func Test_Tracker_End(t *testing.T) {
	testutil.UnitTest(t)
	tracker := newCodeTracker(testProgressChannels, testCancelProgressChannel)
	tracker.End("message")

	assert.Eventually(
		t,
		func() bool {
			for {
				select {
				case p := <-testProgressChannels:
					if p.Value == nil {
						return false
					} else {
						switch value := p.Value.(type) {
						case types.WorkDoneProgressBegin:
							return false
						case types.WorkDoneProgressEnd:
							return value.Message == "message"
						}
					}
				default:
				}
				break //nolint:staticcheck // unconditional termination is intentional — poll once per Eventually tick
			}
			return false
		},
		5*time.Second,
		10*time.Millisecond,
	)
}

// TestGenerateTrackerRoutesToGlobalChannel (IDE-2036-regression) documents the
// CURRENT KNOWN BEHAVIOR of GenerateTracker: it routes progress events to the
// global progress.ToServerProgressChannel rather than to a per-server channel.
//
// This test is intentionally a regression gate. When the TODO in
// GenerateTracker is resolved by migrating to progress.NewTrackerWithChannel,
// this test must be updated to assert per-server isolation instead — preventing
// silent regression to the global-channel path.
//
// Not parallel: inspects the global ToServerProgressChannel, so concurrent
// writers would cause false positives.
func TestGenerateTrackerRoutesToGlobalChannel(t *testing.T) {
	testutil.UnitTest(t)

	// Drain the global channel so prior test runs don't interfere.
	for len(progress.ToServerProgressChannel) > 0 {
		<-progress.ToServerProgressChannel
	}

	logger := zerolog.Nop()
	factory := NewCodeTrackerFactory(&logger)

	ct := factory.GenerateTracker()

	// The returned value must be our internal *tracker type.
	internal, ok := ct.(*tracker)
	if !ok {
		t.Fatalf("GenerateTracker returned unexpected type %T; expected *tracker", ct)
	}

	// The channel held by the tracker must be the global ToServerProgressChannel.
	// When GenerateTracker is migrated to NewTrackerWithChannel this assertion
	// will fail, reminding the author to update the test.
	if internal.channel != progress.ToServerProgressChannel {
		t.Error("GenerateTracker must route to progress.ToServerProgressChannel (global) until IDE-2036 migration is complete")
	}
}
