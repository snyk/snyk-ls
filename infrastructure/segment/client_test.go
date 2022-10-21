/*
 * Copyright 2022 Snyk Ltd.
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

package segment

import (
	"sync"
	"testing"

	"github.com/segmentio/analytics-go"
	segment "github.com/segmentio/analytics-go"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestClient_IdentifyAuthenticatedUser(t *testing.T) {
	s, fakeSegmentClient, fakeApiClient := setupUnitTest(t)

	s.Identify()

	assert.Equal(t, 1, len(fakeApiClient.GetAllCalls(snyk_api.ActiveUserOperation)))
	assert.NotEmpty(t, s.authenticatedUserId)
	assert.Equal(t, 1, len(fakeSegmentClient.trackedEvents))
	assert.Equal(t, fakeSegmentClient.trackedEvents[0], analytics.Identify{
		UserId:      s.authenticatedUserId,
		AnonymousId: config.CurrentConfig().DeviceID(),
	})
}

func TestClient_IdentifyAnonymousUser(t *testing.T) {
	s, _, fakeApiClient := setupUnitTest(t)
	config.CurrentConfig().SetToken("")

	s.Identify()

	assert.Empty(t, s.authenticatedUserId)
	assert.Equal(t, 0, len(fakeApiClient.GetAllCalls(snyk_api.ActiveUserOperation)))
}

func TestClient_IdentifyWithDisabledTelemetry(t *testing.T) {
	s, fakeSegmentClient, _ := setupUnitTest(t)
	config.CurrentConfig().SetTelemetryEnabled(false)

	s.Identify()

	assert.NotEmpty(t, s.authenticatedUserId)
	assert.Equal(t, 0, len(fakeSegmentClient.trackedEvents))
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
				Event:  "Plugin Is Installed",
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

func setupUnitTest(t *testing.T) (*Client, *FakeSegmentClient, *snyk_api.FakeApiClient) {
	testutil.UnitTest(t)
	fakeApiClient := &snyk_api.FakeApiClient{}
	s := NewSegmentClient(fakeApiClient, error_reporting.NewTestErrorReporter()).(*Client)
	fakeSegmentClient := &FakeSegmentClient{mutex: &sync.Mutex{}}
	config.CurrentConfig().SetIntegrationName("Visual Studio Code")
	s.segment = fakeSegmentClient
	return s, fakeSegmentClient, fakeApiClient
}

type FakeSegmentClient struct {
	trackedEvents []segment.Message
	mutex         *sync.Mutex
}

func (f *FakeSegmentClient) Close() error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.trackedEvents = []segment.Message{}
	return nil
}

func (f *FakeSegmentClient) Enqueue(message segment.Message) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.trackedEvents = append(f.trackedEvents, message)
	return nil
}
