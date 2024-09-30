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

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/types"
)

var testProgressChannels = make(chan types.ProgressParams, 10000)
var testCancelProgressChannel = make(chan bool, 10000)

func Test_Tracker_Begin(t *testing.T) {
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
					break
				}
				break //nolint:staticcheck // we want to do this until a message is seen
			}
			return false
		},
		5*time.Second,
		10*time.Millisecond,
	)
}
func Test_Tracker_End(t *testing.T) {
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
					break
				}
				break //nolint:staticcheck // we want to do this until a message is seen
			}
			return false
		},
		5*time.Second,
		10*time.Millisecond,
	)
}
