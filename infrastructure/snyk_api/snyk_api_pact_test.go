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

package snyk_api

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/pact-foundation/pact-go/dsl"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"
)

const (
	consumer     = "SnykLS"
	pactDir      = "./pacts"
	pactProvider = "SnykApi"
	orgUUID      = "00000000-0000-0000-0000-000000000023"
)

// Common test data
var pact dsl.Pact
var client SnykApiClient

func TestSnykApiPact(t *testing.T) {
	testutil.NotOnWindows(t, "we don't have a pact cli")
	testutil.UnitTest(t)

	setupPact()
	defer pact.Teardown()

	defer func() {
		if err := pact.WritePact(); err != nil {
			t.Fatal(err)
		}
	}()

	t.Run("Get SAST enablement", func(t *testing.T) {
		expectedResponse := SastResponse{
			SastEnabled:                 true,
			LocalCodeEngine:             LocalCodeEngine{Enabled: false},
			ReportFalsePositivesEnabled: false,
			AutofixEnabled:              false,
		}

		// when no org is set, the Go Application framework calls the API to obtain the default org
		interactionOrg := pact.AddInteraction().WithRequest(dsl.Request{
			Method: "GET",
			Path:   dsl.String("/rest/self"),
			Query:  dsl.MapMatcher{"version": dsl.String("2022-09-15~experimental")},
			Headers: dsl.MapMatcher{
				"Authorization": dsl.Regex("token fc763eba-0905-41c5-a27f-3934ab26786c", `^token [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
			},
		}).WillRespondWith(dsl.Response{
			Status: 200,
			Headers: dsl.MapMatcher{
				"Content-Type": dsl.String("application/json"),
			},
			// don't return an org, so we can see that the sastEnabled call is done without org parameter
			Body: dsl.String(""),
		})
		interactionOrg.Description = "happy path without org as query parameter, org call"

		interactionConfigSettings := pact.AddInteraction().WithRequest(dsl.Request{
			Method: "GET",
			Path:   dsl.String("/cli-config/settings/sast"),
			Headers: dsl.MapMatcher{
				"Content-Type":  dsl.String("application/json"),
				"Authorization": dsl.Regex("token fc763eba-0905-41c5-a27f-3934ab26786c", `^token [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
			},
		}).WillRespondWith(dsl.Response{
			Status: 200,
			Headers: dsl.MapMatcher{
				"Content-Type": dsl.String("application/json"),
			},
			Body: dsl.Match(expectedResponse),
		})
		interactionConfigSettings.Description = "happy path without org as query parameter"

		test := func() error {
			_, err := client.SastSettings()
			if err != nil {
				return err
			}
			return nil
		}

		err := pact.Verify(test)

		assert.NoError(t, err)
	})

	t.Run("Get SAST enablement with org", func(t *testing.T) {
		organization := orgUUID
		config.CurrentConfig().SetOrganization(organization)

		expectedResponse := SastResponse{
			SastEnabled:                 true,
			LocalCodeEngine:             LocalCodeEngine{Enabled: false},
			ReportFalsePositivesEnabled: false,
			AutofixEnabled:              false,
		}

		matcher := dsl.MapMatcher{}
		matcher["org"] = dsl.String(organization)

		interaction := pact.AddInteraction().
			WithRequest(dsl.Request{
				Method: "GET",
				Path:   dsl.String("/cli-config/settings/sast"),
				Query:  matcher,
				Headers: dsl.MapMatcher{
					"Content-Type":  dsl.String("application/json"),
					"Authorization": dsl.Regex("token fc763eba-0905-41c5-a27f-3934ab26786c", `^token [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
				},
			}).WillRespondWith(dsl.Response{
			Status: 200,
			Headers: dsl.MapMatcher{
				"Content-Type": dsl.String("application/json"),
			},
			Body: dsl.Match(expectedResponse),
		})
		interaction.Description = "happy path with org as query param"

		test := func() error {
			_, err := client.SastSettings()
			if err != nil {
				return err
			}
			return nil
		}

		err := pact.Verify(test)

		assert.NoError(t, err)
	})

	t.Run("Get feature flag status", func(t *testing.T) {
		organization := orgUUID
		config.CurrentConfig().SetOrganization(organization)
		var featureFlagType FeatureFlagType = "snykCodeConsistentIgnores"

		expectedResponse := FFResponse{
			Ok:          true,
			UserMessage: nil,
		}

		matcher := dsl.MapMatcher{}
		matcher["org"] = dsl.String(organization)

		interaction := pact.AddInteraction().
			WithRequest(dsl.Request{
				Method: "GET",
				Path:   dsl.String("/cli-config/feature-flag/" + featureFlagType),
				Query:  matcher,
				Headers: dsl.MapMatcher{
					"Content-Type":  dsl.String("application/json"),
					"Authorization": dsl.Regex("token fc763eba-0905-41c5-a27f-3934ab26786c", `^token [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
				},
			}).WillRespondWith(dsl.Response{
			Status: 200,
			Headers: dsl.MapMatcher{
				"Content-Type": dsl.String("application/json"),
			},
			Body: dsl.Match(expectedResponse),
		})
		interaction.Description = "feature flag with org as query param"

		test := func() error {
			_, err := client.FeatureFlagSettings("snykCodeConsistentIgnores")
			if err != nil {
				return err
			}
			return nil
		}

		err := pact.Verify(test)

		assert.NoError(t, err)
	})
}

func setupPact() {
	pact = dsl.Pact{
		Consumer: consumer,
		Provider: pactProvider,
		PactDir:  pactDir,
	}

	// Proactively start service to get access to the port
	pact.Setup(true)

	c := config.CurrentConfig()
	c.UpdateApiEndpoints(fmt.Sprintf("http://localhost:%d", pact.Server.Port))
	client = NewSnykApiClient(func() *http.Client { return c.Engine().GetNetworkAccess().GetHttpClient() })
}
