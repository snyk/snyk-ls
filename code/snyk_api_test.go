package code

import (
	"fmt"
	"testing"

	"github.com/pact-foundation/pact-go/dsl"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestSnykApiService_GetSastEnablement_returns(t *testing.T) {
	testutil.UnitTest(t)
	pact := &dsl.Pact{
		Consumer: "SnykLS",
		Provider: "SnykApi",
		PactDir:  pactDir,
	}
	defer pact.Teardown()

	expectedResponse := sastResponse{
		SastEnabled:                 true,
		LocalCodeEngine:             localCodeEngine{Enabled: false},
		ReportFalsePositivesEnabled: false,
	}

	pact.AddInteraction().WithRequest(dsl.Request{
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

	test := func() error {
		s := NewSnykApiClient(fmt.Sprintf("http://localhost:%d", pact.Server.Port))
		_, _, _, err := s.SastEnabled()
		if err != nil {
			return err
		}
		return nil
	}

	err := pact.Verify(test)

	assert.NoError(t, err)
}
