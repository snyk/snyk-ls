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
	"time"

	"github.com/stretchr/testify/require"
)

func RequireEventuallyReceive[T any](t *testing.T, ch <-chan T, waitFor, tick time.Duration, msgAndArgs ...any) T {
	t.Helper()

	var capturedValue T
	channelClosed := false
	require.Eventually(t, func() bool {
		select {
		case potentialCapturedValue, ok := <-ch:
			if !ok {
				// Channel is closed, exit the loop, then we will fail the test.
				channelClosed = true
				return true
			}
			capturedValue = potentialCapturedValue
			return true
		default:
			return false
		}
	}, waitFor, tick, msgAndArgs...)

	if channelClosed {
		if len(msgAndArgs) > 0 {
			t.Log(msgAndArgs...)
		}
		t.Fatal("Channel was closed before receiving a value (context printed above)")
	}

	return capturedValue
}
