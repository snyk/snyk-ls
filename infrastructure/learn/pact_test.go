/*
 * © 2023 Snyk Limited
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

package learn

import (
	"fmt"
	"testing"

	"github.com/pact-foundation/pact-go/dsl"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	errorreporting "github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testutil"
)

const (
	consumer     = "SnykLS"
	pactDir      = "./pacts"
	pactProvider = "SnykLearn"
)

// Common test data
var pact dsl.Pact

func setupPact(t *testing.T) {
	testutil.NotOnWindows(t, "we don't have a pact cli")
	testutil.UnitTest(t)

	pact.LogLevel = "DEBUG"

	pact = dsl.Pact{
		Consumer: consumer,
		Provider: pactProvider,
		PactDir:  pactDir,
	}
}

func TestSnykLearnServicePact(t *testing.T) { // nolint:gocognit // this is a test wrapper function
	setupPact(t)
	defer pact.Teardown()

	defer func() {
		if err := pact.WritePact(); err != nil {
			t.Fatal(err)
		}
	}()

	t.Run("Lessons", func(t *testing.T) {
		expectedResponse := []Lesson{}
		pact.AddInteraction().
			Given("nocache").
			UponReceiving("/lessons endpoint").
			WithRequest(
				dsl.Request{
					Method:  "GET",
					Path:    dsl.String("/v1/learn/lessons"),
					Headers: headerMatcher(),
				}).
			WillRespondWith(dsl.Response{
				Status: 200,
				Headers: dsl.MapMatcher{
					"Content-Type": dsl.String("application/json"),
				},
				Body: dsl.Match(expectedResponse),
			})

		test := func() (err error) {
			c := config.New()
			c.UpdateApiEndpoints(fmt.Sprintf("http://%s", hostWithPort()))
			httpClientFunc := c.Engine().GetNetworkAccess().GetUnauthorizedHttpClient

			cut := New(c, httpClientFunc, errorreporting.NewTestErrorReporter()).(*serviceImpl)

			_, err = cut.GetAllLessons()

			assert.NoError(t, err)
			assert.True(t, cut.lessonsByEcosystemCache.Len() > 0, "didn't save the lessons in the cache")
			return err
		}

		err := pact.Verify(test)

		if err != nil {
			t.Fatalf("Error on verify: %v", err)
		}
	})
}

func headerMatcher() dsl.MapMatcher {
	m := dsl.MapMatcher{}
	m["Host"] = dsl.Regex("http://localhost:1234", ".*")
	m["User-Agent"] = dsl.Regex("go-http-client/1.1", ".*")
	m["Accept-Encoding"] = dsl.String("gzip")
	m["Version"] = dsl.Regex("HTTP/1.1", "HTTP\\/.*")
	return m
}

func hostWithPort() string {
	return fmt.Sprintf("%s:%d", pact.Host, pact.Server.Port)
}
