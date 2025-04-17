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

package testsupport

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func AssertChannelIsEmpty[T any](t *testing.T, channel chan T) {
	t.Helper()

	var msgs []T
drainingLoop:
	for {
		select {
		case msg, ok := <-channel:
			if !ok {
				// Handle closed being the end of the messages.
				break drainingLoop
			}
			msgs = append(msgs, msg)
		default:
			break drainingLoop
		}
	}
	if len(msgs) != 0 {
		// Fatal failure (stop execution), as mishandled channels in Go can cause panics and infinite waits.
		assert.FailNowf(t, "Expected channel to be empty, but there were remaining messages.",
			"Number of remaining messages: %d\nvvv Messages: vvv\n%v", len(msgs), msgs)
	}
}
