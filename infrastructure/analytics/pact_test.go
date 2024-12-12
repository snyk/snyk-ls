package analytics

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pact-foundation/pact-go/dsl"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/instrumentation"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/utils"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestAnalyticsProviderPactV2(t *testing.T) {
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
	expectedBody := testGetAnalyticsV2Payload(t)
	v2InstrumentationData := utils.ValueOf(json.Marshal(expectedBody))

	var test = func() (err error) {
		//prepare
		c.SetToken("token")
		c.SetOrganization(orgUUID)
		c.UpdateApiEndpoints(base)

		// invoke function under test
		err = SendAnalyticsToAPI(c, v2InstrumentationData)
		assert.NoError(t, err)

		return nil
	}

	pact.
		AddInteraction().
		Given("Analytics data is ready").
		UponReceiving("A request to create analytics data").
		WithRequest(dsl.Request{
			Method: "POST",
			Path:   dsl.String("/hidden/orgs/" + orgUUID + "/analytics"),
			Body:   expectedBody,
		}).
		WillRespondWith(dsl.Response{
			Status:  201,
			Headers: dsl.MapMatcher{"Content-Type": dsl.Term("application/json", `^application\/json$`)},
			Body:    map[string]interface{}{},
		})

	// Verify runs the current test case against a Mock Service.
	if err := pact.Verify(test); err != nil {
		t.Fatalf("Error on Verify: %v", err)
	}
}

func TestAnalyticsPluginInstalled(t *testing.T) {
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
	v2Object, expectedOutputData := testGetAnalyticsEventParam(t)
	inputData := utils.ValueOf(json.Marshal(v2Object))

	var test = func() (err error) {
		//prepare
		c.SetToken("token")
		c.SetOrganization(orgUUID)
		c.UpdateApiEndpoints(base)

		// invoke function under test
		err = SendAnalyticsToAPI(c, inputData)
		assert.NoError(t, err)

		return nil
	}

	pact.
		AddInteraction().
		Given("Analytics data is ready").
		UponReceiving("An AnalyticsEventParam json payload").
		WithRequest(dsl.Request{
			Method: "POST",
			Path:   dsl.String("/hidden/orgs/" + orgUUID + "/analytics"),
			Body:   expectedOutputData,
		}).
		WillRespondWith(dsl.Response{
			Status:  201,
			Headers: dsl.MapMatcher{"Content-Type": dsl.Term("application/json", `^application\/json$`)},
			Body:    map[string]interface{}{},
		})

	// Verify runs the current test case against a Mock Service.
	if err := pact.Verify(test); err != nil {
		t.Fatalf("Error on Verify: %v", err)
	}
}

func testGetAnalyticsEventParam(t *testing.T) (types.AnalyticsEventParam, any) {
	t.Helper()

	now := time.Now()
	event := types.AnalyticsEventParam{
		InteractionType: "plugin installed",
		Category:        []string{"install"},
		Status:          string(analytics.Success),
		TimestampMs:     now.UnixMilli(),
		TargetId:        "pkg:github/package-url/purl-spec@244fd47e07d1004f0aed9c",
		InteractionUUID: uuid.NewString(),
	}

	ic := testPopulateICWithStdValues(t, event.InteractionUUID)
	ic.SetInteractionType(event.InteractionType)
	ic.SetCategory(event.Category)
	ic.SetTimestamp(now)

	v2InstrumentationObject, _ := analytics.GetV2InstrumentationObject(ic)

	return event, v2InstrumentationObject
}

func testGetAnalyticsV2Payload(t *testing.T) any {
	t.Helper()
	ic := testPopulateICWithStdValues(t, "00000000-0000-0000-0000-000000000000")

	summary := createTestSummary()
	ic.SetTestSummary(summary)
	ic.SetInteractionType("Scan done")
	ic.SetCategory([]string{"oss", "test"})
	ic.SetDuration(10 * time.Millisecond)

	actualV2InstrumentationObject, _ := analytics.GetV2InstrumentationObject(ic)

	return actualV2InstrumentationObject
}

func testPopulateICWithStdValues(t *testing.T, interactionUUID string) analytics.InstrumentationCollector {
	t.Helper()
	gafConfig := configuration.NewWithOpts(
		configuration.WithAutomaticEnv(),
	)
	conf := config.CurrentConfig()
	ic := analytics.NewInstrumentationCollector()

	ua := networking.UserAgent(networking.UaWithConfig(gafConfig), networking.UaWithApplication("snyk-ls", config.Version))
	ic.SetUserAgent(ua)

	iid := instrumentation.AssembleUrnFromUUID(interactionUUID)
	ic.SetInteractionId(iid)
	ic.SetTimestamp(time.Now())
	ic.SetStage("dev")
	ic.SetStatus("success") //or get result status from scan
	ic.SetInteractionId(iid)
	ic.SetTargetId("pkg:github/package-url/purl-spec@244fd47e07d1004f0aed9c")
	ic.AddExtension("device_id", conf.DeviceID())
	ic.SetType("analytics")
	return ic
}

func createTestSummary() json_schemas.TestSummary {
	testSummary := json_schemas.TestSummary{
		Results: []json_schemas.TestSummaryResult{{
			Severity: "critical",
			Total:    2,
			Open:     0,
			Ignored:  0,
		}, {
			Severity: "high",
			Total:    3,
			Open:     0,
			Ignored:  0,
		}, {
			Severity: "medium",
			Total:    4,
			Open:     0,
			Ignored:  0,
		}, {
			Severity: "low",
			Total:    5,
			Open:     0,
			Ignored:  0,
		}},
		Type: string("oss"),
	}
	return testSummary
}
