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

package notification

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/internal/concurrency"
)

var params = lsp.AuthenticationParams{Token: "test event"}

func TestSendReceive(t *testing.T) {
	Send(params)
	output, _ := Receive()
	assert.Equal(t, params, output)
}

func TestCreateListener(t *testing.T) {
	called := concurrency.AtomicBool{}
	CreateListener(func(event interface{}) {
		called.Set(true)
	})
	defer DisposeListener()
	Send(params)
	assert.Eventually(t, func() bool {
		return called.Get()
	}, 2*time.Second, time.Second)
}
