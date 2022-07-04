package code

import (
	"fmt"
	"testing"

	"github.com/pact-foundation/pact-go/dsl"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestSnykApiService_GetSastEnablement_returns(t *testing.T) {
	testutil.UnitTest(t)
	pact := testutil.Pact(t, pactDir, "SnykApi")

	expectedResponse := sastResponse{
		SastEnabled:                 true,
		LocalCodeEngine:             localCodeEngine{Enabled: false},
		ReportFalsePositivesEnabled: false,
	}

	interaction := pact.AddInteraction().WithRequest(dsl.Request{
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
	interaction.Description = "happy path without org as query parameter"

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

func TestSnykApiService_GetSastEnablementWithOrg_returns(t *testing.T) {
	testutil.UnitTest(t)
	pact := testutil.Pact(t, pactDir, "SnykApi")
	organization := "test-org with characters (e.g. %) to be encoded!"
	config.CurrentConfig().SetOrganization(organization)

	expectedResponse := sastResponse{
		SastEnabled:                 true,
		LocalCodeEngine:             localCodeEngine{Enabled: false},
		ReportFalsePositivesEnabled: false,
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

func TestSnykApiService_GetActiveUser(t *testing.T) {
	testutil.UnitTest(t)
	pact := testutil.Pact(t, pactDir, "SnykApi")
	interaction := pact.AddInteraction().
		WithRequest(dsl.Request{
			Method: "GET",
			Path:   dsl.String("/user/me"),
			Headers: dsl.MapMatcher{
				"Content-Type":  dsl.String("application/json"),
				"Authorization": dsl.Regex("token fc763eba-0905-41c5-a27f-3934ab26786c", `^token [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
			},
		}).WillRespondWith(dsl.Response{
		Status: 200,
		Headers: dsl.MapMatcher{
			"Content-Type": dsl.String("application/json"),
		},
		Body: activeUserResponse{
			Id: "fc763eba-0905-41c5-a27f-3934ab26786a",
		},
	})
	interaction.Description = "Get active user"

	test := func() error {
		s := NewSnykApiClient(fmt.Sprintf("http://localhost:%d", pact.Server.Port))
		user, err := s.GetActiveUser()
		if err != nil {
			return err
		}
		assert.Equal(t, "fc763eba-0905-41c5-a27f-3934ab26786a", user.Id)
		return nil
	}

	err := pact.Verify(test)

	assert.NoError(t, err)
}
