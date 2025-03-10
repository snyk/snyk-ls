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

package code

import (
	"github.com/google/uuid"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_getExplain_Endpoint(t *testing.T) {
	t.Run("should return default explain endpoint", func(t *testing.T) {
		c := testutil.UnitTest(t)
		random, _ := uuid.NewRandom()
		orgUUID := random.String()
		c.SetOrganization(orgUUID)
		actualEndpoint := getExplainEndpoint(c).String()
		expectedEndpoint := "https://api.snyk.io/rest/orgs/" + orgUUID + "/explain-fix"
		assert.Equal(t, expectedEndpoint, actualEndpoint)
	})
}

func Test_GetExplain_Endpoint_With_Updated_API_Endpoints(t *testing.T) {
	t.Run("should return correct explain endpoint", func(t *testing.T) {
		c := testutil.UnitTest(t)
		random, _ := uuid.NewRandom()
		orgUUID := random.String()
		c.SetOrganization(orgUUID)
		c.UpdateApiEndpoints("https://test.snyk.io")
		actualEndpoint := getExplainEndpoint(c).String()
		expectedEndpoint := "https://test.snyk.io/rest/orgs/" + orgUUID + "/explain-fix"
		assert.Equal(t, expectedEndpoint, actualEndpoint)
	})
}
