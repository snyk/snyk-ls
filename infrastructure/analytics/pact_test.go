package analytics

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"testing"

	"github.com/pact-foundation/pact-go/dsl"
)

func TestAnalyticsProviderPact(t *testing.T) {
	pact := &dsl.Pact{
		Consumer: "snyk-ls",
		Provider: "AnalyticsProvider",
		LogDir:   "logs",
		PactDir:  "./pacts",
		LogLevel: "DEBUG",
	}

	defer pact.Teardown()

	var test = func() (err error) {
		u := fmt.Sprintf("http://localhost:%d/rest/api/orgs/org_id/analytics", pact.Server.Port)

		expectedBody := getExpectedBodyRequest()
		bodyBytes, err := json.Marshal(expectedBody)

		if err != nil {
			fmt.Printf("Error marshaling payload: %v\n", err)
			return err
		}

		req, err := http.NewRequest("POST", u, bytes.NewBuffer(bodyBytes))
		if err != nil {
			return err
		}

		req.Header.Set("Content-Type", "application/json")
		if _, err = http.DefaultClient.Do(req); err != nil {
			return err
		}

		return nil
	}

	pact.
		AddInteraction().
		Given("Analytics data is ready").
		UponReceiving("A request to create analytics data").
		WithRequest(dsl.Request{
			Method:  "POST",
			Path:    dsl.String("/rest/api/orgs/org_id/analytics"),
			Headers: dsl.MapMatcher{"Content-Type": dsl.Term("application/json", `^application\/json$`)},
			Body:    getExpectedBodyRequest(),
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
				"deviceId":                        "unique-uuid",
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
