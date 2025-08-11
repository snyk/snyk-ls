/*
 * © 2022-2024 Snyk Limited
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
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/pact-foundation/pact-go/dsl"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
)

const (
	consumer     = "SnykLS"
	pactDir      = "./pacts"
	pactProvider = "SnykCodeApi"

	orgUUID             = "00000000-0000-0000-0000-000000000023"
	sessionTokenMatcher = "^token [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
	uuidMatcher         = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)

// Common test data
var pact dsl.Pact
var client *SnykCodeHTTPClient

//nolint:gocyclo // TODO: address tech debt
func TestSnykCodeBackendServicePact(t *testing.T) {
	testsupport.NotOnWindows(t, "we don't have a pact cli")
	testutil.UnitTest(t)

	setupPact(t)
	config.CurrentConfig().UpdateApiEndpoints("http://localhost")
	defer pact.Teardown()

	defer func() {
		if err := pact.WritePact(); err != nil {
			t.Fatal(err)
		}
	}()
	
	t.Run("Get filters", func(*testing.T) {
		pact.AddInteraction().UponReceiving("Get filters").WithRequest(dsl.Request{
			Method: "GET",
			Path:   dsl.String("/filters"),
			Headers: dsl.MapMatcher{
				"Content-Type":    dsl.String("application/json"),
				"snyk-request-id": getSnykRequestIdMatcher(),
			},
		}).WillRespondWith(dsl.Response{
			Status: 200,
			Headers: dsl.MapMatcher{
				"Content-Type": dsl.String("application/json"),
			},
			Body: dsl.Match(FiltersResponse{}),
		})

		test := func() error {
			if _, err := client.GetFilters(context.Background()); err != nil {
				return err
			}

			return nil
		}

		err := pact.Verify(test)

		assert.NoError(t, err)
	})
}

func setupPact(t *testing.T) {
	t.Helper()
	pact = dsl.Pact{
		Consumer: consumer,
		Provider: pactProvider,
		PactDir:  pactDir,
	}

	// Proactively start service to get access to the port
	pact.Setup(true)

	t.Setenv("DEEPROXY_API_URL", fmt.Sprintf("http://localhost:%d", pact.Server.Port))
	c := config.CurrentConfig()
	c.SetOrganization(orgUUID)

	client = NewSnykCodeHTTPClient(c, NewCodeInstrumentor(), newTestCodeErrorReporter(),
		func() *http.Client { return c.Engine().GetNetworkAccess().GetHttpClient() })
}

func getPutPostHeaderMatcher() dsl.MapMatcher {
	return dsl.MapMatcher{
		"Content-Type":     dsl.String("application/octet-stream"),
		"Content-Encoding": dsl.String("gzip"),
		"Session-Token":    dsl.Regex("token fc763eba-0905-41c5-a27f-3934ab26786c", sessionTokenMatcher),
		"snyk-org-name":    dsl.Regex(orgUUID, uuidMatcher),
		"snyk-request-id":  getSnykRequestIdMatcher(),
	}
}

func getPutPostBodyMatcher() dsl.Matcher {
	return dsl.Like(make([]byte, 1))
}

func getSnykRequestIdMatcher() dsl.Matcher {
	return dsl.Regex("fc763eba-0905-41c5-a27f-3934ab26786c", uuidMatcher)
}

func TestSnykCodeBackendServicePact_LocalCodeEngine(t *testing.T) {
	testsupport.NotOnWindows(t, "we don't have a pact cli")
	testutil.UnitTest(t)

	setupPact(t)
	config.CurrentConfig().SetSnykCodeApi(fmt.Sprintf("http://localhost:%d", pact.Server.Port))
	config.CurrentConfig().SetOrganization(orgUUID)
	defer pact.Teardown()

	pact.AddInteraction().UponReceiving("Get filters").WithRequest(dsl.Request{
		Method: "GET",
		Path:   dsl.String("/filters"),
		Headers: dsl.MapMatcher{
			"Content-Type":    dsl.String("application/json"),
			"snyk-request-id": getSnykRequestIdMatcher(),
			"Session-Token":   dsl.Regex("token fc763eba-0905-41c5-a27f-3934ab26786c", sessionTokenMatcher),
			"Authorization":   dsl.Regex("token fc763eba-0905-41c5-a27f-3934ab26786c", sessionTokenMatcher),
		},
	}).WillRespondWith(dsl.Response{
		Status: 200,
		Headers: dsl.MapMatcher{
			"Content-Type": dsl.String("application/json"),
		},
		Body: dsl.Match(FiltersResponse{}),
	})

	test := func() error {
		if _, err := client.GetFilters(context.Background()); err != nil {
			return err
		}
		return nil
	}

	err := pact.Verify(test)

	assert.NoError(t, err)
}
