package segment

import (
	"testing"

	segment "github.com/segmentio/analytics-go"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/observability/user_behaviour"
)

func Test(t *testing.T) {
	s := NewSegmentClient("user", user_behaviour.VisualStudioCode)
	fakeSegmentClient := &FakeSegmentClient{}
	s.(*Client).segment = fakeSegmentClient
	tests := []struct {
		name   string
		track  func()
		output segment.Track
	}{
		{
			name: "Analysis Is Ready",
			track: func() {
				s.AnalysisIsReady(user_behaviour.AnalysisIsReadyProperties{
					AnalysisType: user_behaviour.CodeQuality,
					Result:       user_behaviour.Success,
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
				s.AnalysisIsTriggered(user_behaviour.AnalysisIsTriggeredProperties{
					AnalysisType:    []user_behaviour.AnalysisType{user_behaviour.CodeSecurity, user_behaviour.CodeQuality},
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
				s.IssueHoverIsDisplayed(user_behaviour.IssueHoverIsDisplayedProperties{
					IssueId:   "javascript%2Fdc_interfile_project%2FHttpToHttps",
					IssueType: user_behaviour.CodeSecurityVulnerability,
					Severity:  user_behaviour.Medium,
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
				s.PluginIsUninstalled(user_behaviour.PluginIsUninstalledProperties{})
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
				s.PluginIsInstalled(user_behaviour.PluginIsInstalledProperties{})
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
