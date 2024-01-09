package analytics

import (
	"encoding/json"
	"fmt"
	"log"
	"testing"

	"github.com/pact-foundation/pact-go/dsl"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestAnalyticsProviderPact(t *testing.T) {
	testutil.NotOnWindows(t, "we don't have a pact cli")
	c := testutil.UnitTest(t)

	pact := &dsl.Pact{
		Consumer: "snyk-ls",
		Provider: "AnalyticsProvider",
		LogDir:   "logs",
		PactDir:  "./pacts",
		LogLevel: "DEBUG",
	}

	defer pact.Teardown()

	pact.Setup(true)
	base := fmt.Sprintf("http://localhost:%d", pact.Server.Port)
	orgUUID := "54125374-3f93-402e-b693-e0724794d71f"

	var test = func() (err error) {
		//prepare
		c.SetToken("token")
		c.SetOrganization(orgUUID)
		c.UpdateApiEndpoints(base)
		expectedBody := getExpectedBodyRequest()
		bodyBytes, err := json.Marshal(expectedBody)
		assert.NoError(t, err)

		// invoke function under test
		err = SendAnalyticsToAPI(c, bodyBytes)
		assert.NoError(t, err)

		return nil
	}

	pact.
		AddInteraction().
		Given("Analytics data is ready").
		UponReceiving("A request to create analytics data").
		WithRequest(dsl.Request{
			Method: "POST",
			Path:   dsl.String("/rest/api/orgs/" + orgUUID + "/analytics"),
			Body:   getExpectedBodyRequest(),
		}).
		WillRespondWith(dsl.Response{
			Status:  201,
			Headers: dsl.MapMatcher{"Content-Type": dsl.Term("application/json", `^application\/json$`)},
			Body:    map[string]interface{}{},
		})

	// Verify runs the current test case against a Mock Service.
	if err := pact.Verify(test); err != nil {
		log.Fatalf("Error on Verify: %v", err)
	}
}

func getExpectedBodyRequest() map[string]interface{} {
	return map[string]interface{}{
		"data": map[string]interface{}{
			"type": "analytics",
			"attributes": map[string]interface{}{
				"device_id":                       "unique-uuid",
				"application":                     "snyk-cli",
				"application_version":             "1.1233.0",
				"os":                              "Windows",
				"arch":                            "AMD64",
				"integration_name":                "IntelliJ",
				"integration_version":             "2.5.5",
				"integration_environment":         "IntelliJ Ultimate",
				"integration_environment_version": "2023.3",
				"event_type":                      "Scan done",
				"status":                          "Succeeded",
				"scan_type":                       "Snyk Open Source",
				"unique_issue_count": map[string]interface{}{
					"critical": 15,
					"high":     10,
					"medium":   1,
					"low":      2,
				},
				"duration_ms":        "1000",
				"timestamp_finished": "2023-09-01T12:00:00Z",
			},
		},
	}
}
