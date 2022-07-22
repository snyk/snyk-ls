package segment

import (
	"testing"

	segment "github.com/segmentio/analytics-go"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestClient_GetUserInfo(t *testing.T) {
	s, _, fakeApiClient := setupUnitTest(t)
	userId := s.GetOrUpdateUserInfo()
	assert.Equal(t, 1, len(fakeApiClient.GetAllCalls(snyk_api.ActiveUserOperation)))
	assert.NotEmpty(t, userId)
}

func Test_AnalyticEvents(t *testing.T) {
	s, fakeSegmentClient, _ := setupUnitTest(t)
	tests := []struct {
		name   string
		track  func()
		output segment.Track
	}{
		{
			name: "Analysis Is Ready",
			track: func() {
				s.AnalysisIsReady(ux.AnalysisIsReadyProperties{
					AnalysisType: ux.CodeQuality,
					Result:       ux.Success,
				})
			},
			output: segment.Track{
				UserId: "user",
				Event:  "Analysis Is Ready",
				Properties: segment.Properties{}.
					Set("analysisType", "Snyk Code Quality").
					Set("ide", "Visual Studio Code").
					Set("itly", true).
					Set("result", "Success"),
			},
		},
		{
			name: "Analysis Is Triggered",
			track: func() {
				s.AnalysisIsTriggered(ux.AnalysisIsTriggeredProperties{
					AnalysisType:    []ux.AnalysisType{ux.CodeSecurity, ux.CodeQuality},
					TriggeredByUser: true,
				})
			},
			output: segment.Track{
				UserId: "user",
				Event:  "Analysis Is Triggered",
				Properties: segment.Properties{}.
					Set("analysisType", []string{
						"Snyk Code Security",
						"Snyk Code Quality",
					}).
					Set("ide", "Visual Studio Code").
					Set("itly", true).
					Set("triggeredByUser", true),
			},
		},
		{
			name: "Issue Hover Is Displayed",
			track: func() {
				s.IssueHoverIsDisplayed(ux.IssueHoverIsDisplayedProperties{
					IssueId:   "javascript%2Fdc_interfile_project%2FHttpToHttps",
					IssueType: ux.CodeSecurityVulnerability,
					Severity:  ux.Medium,
				})
			},
			output: segment.Track{
				UserId: "user",
				Event:  "Issue Hover Is Displayed",
				Properties: segment.Properties{}.
					Set("ide", "Visual Studio Code").
					Set("issueId", "javascript%2Fdc_interfile_project%2FHttpToHttps").
					Set("issueType", "Code Security Vulnerability").
					Set("itly", true).
					Set("severity", "Medium"),
			},
		},
		{
			name: "Plugin Is Uninstalled",
			track: func() {
				s.PluginIsUninstalled(ux.PluginIsUninstalledProperties{})
			},
			output: segment.Track{
				UserId: "user",
				Event:  "Issue Hover Is Displayed",
				Properties: segment.Properties{}.
					Set("ide", "Visual Studio Code").
					Set("itly", true),
			},
		},
		{
			name: "Plugin Is Installed",
			track: func() {
				s.PluginIsInstalled(ux.PluginIsInstalledProperties{})
			},
			output: segment.Track{
				UserId: "user",
				Event:  "Issue Hover Is Displayed",
				Properties: segment.Properties{}.
					Set("ide", "Visual Studio Code").
					Set("itly", true),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.track()
			assert.ObjectsAreEqual(test.output, fakeSegmentClient.trackedEvents[0])
		})
	}
}

func setupUnitTest(t *testing.T) (ux.Analytics, *FakeSegmentClient, *snyk_api.FakeApiClient) {
	testutil.UnitTest(t)
	fakeApiClient := &snyk_api.FakeApiClient{}
	s := NewSegmentClient(fakeApiClient, ux.VisualStudioCode)
	fakeSegmentClient := &FakeSegmentClient{}
	s.(*Client).segment = fakeSegmentClient
	return s, fakeSegmentClient, fakeApiClient
}

type FakeSegmentClient struct {
	trackedEvents []segment.Track
}

func (f *FakeSegmentClient) Close() error {
	f.trackedEvents = []segment.Track{}
	return nil
}

func (f *FakeSegmentClient) Enqueue(message segment.Message) error {
	f.trackedEvents = append(f.trackedEvents, message.(segment.Track))
	return nil
}
