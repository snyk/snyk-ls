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

package workspace

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestWorkspace_TrustRequests(t *testing.T) {
	c := testutil.UnitTest(t)
	w := New(c, nil, nil, nil, nil, nil)
	w.StartRequestTrustCommunication()
	w.IsTrustRequestOngoing()
	assert.True(t, w.IsTrustRequestOngoing())
	w.EndRequestTrustCommunication()
	assert.False(t, w.IsTrustRequestOngoing())
}
