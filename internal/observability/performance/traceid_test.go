/*
 * © 2022 Snyk Limited All rights reserved.
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

package performance

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestGetContextWithTraceId(t *testing.T) {
	t.Run("sets trace_id", func(t *testing.T) {
		// prepare
		ctx := context.Background()
		u := uuid.New().String()

		// act
		newCtx := GetContextWithTraceId(ctx, u)

		// assert
		traceId, err := GetTraceId(newCtx)
		if err != nil {
			assert.Fail(t, "Couldn't obtain trace_id")
		}

		assert.Equal(t, traceId, u)
	})
}
