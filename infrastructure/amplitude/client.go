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

package amplitude

import (
	"strings"

	"github.com/amplitude/analytics-go/amplitude"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"

	// segment "github.com/segmentio/analytics-go"

	"github.com/snyk/snyk-ls/ampli"
	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
)

type Client struct {
	authenticatedUserId string
	destination         *SegmentPlugin
	snykApiClient       snyk_api.SnykApiClient
	errorReporter       error_reporting.ErrorReporter
}

type captureEvent func(userId string, eventOptions ...ampli.EventOptions)

func NewAmplitudeClient(snykApiClient snyk_api.SnykApiClient, errorReporter error_reporting.ErrorReporter) ux2.Analytics {
	ampliConfig := amplitude.NewConfig("")

	ampli.Instance.Load(ampli.LoadOptions{
		Client: ampli.LoadClientOptions{
			Configuration: ampliConfig,
		},
	})

	segmentPlugin := NewSegmentPlugin()
	ampli.Instance.Client.Add(segmentPlugin)

	client := &Client{
		destination:   segmentPlugin,
		snykApiClient: snykApiClient,
		errorReporter: errorReporter,
	}

	return client
}

func (c *Client) Initialise() {
	go c.captureInstalledEvent()
}

func (c *Client) Shutdown() error {
	return c.destination.Shutdown()
}

func (c *Client) AnalysisIsReady(properties ux2.AnalysisIsReadyProperties) {
	log.Info().Str("method", "AnalysisIsReady").Msg("analytics enqueued")
	analysisType := ampli.AnalysisIsReadyAnalysisType(properties.AnalysisType)
	ide := ampli.AnalysisIsReadyIde(getIdeProperty())
	result := ampli.AnalysisIsReadyResult(properties.Result)
	event := ampli.AnalysisIsReady.Builder().AnalysisType(analysisType).Ide(ide).Result(result).DurationInSeconds(properties.DurationInSeconds).FileCount(properties.FileCount).Build()

	captureFn := func(authenticatedUserId string, eventOptions ...ampli.EventOptions) {
		ampli.Instance.AnalysisIsReady(authenticatedUserId, event, eventOptions...)
	}
	c.enqueueEvent(captureFn)
}

func (c *Client) AnalysisIsTriggered(properties ux2.AnalysisIsTriggeredProperties) {
	log.Info().Str("method", "AnalysisIsTriggered").Msg("analytics enqueued")
	analysisTypes := make([]string, 0, len(properties.AnalysisType))
	for _, analysisType := range properties.AnalysisType {
		analysisTypes = append(analysisTypes, string(analysisType))
	}
	ide := ampli.AnalysisIsTriggeredIde(getIdeProperty())
	event := ampli.AnalysisIsTriggered.Builder().AnalysisType(analysisTypes).Ide(ide).TriggeredByUser(properties.TriggeredByUser).Build()

	captureFn := func(authenticatedUserId string, eventOptions ...ampli.EventOptions) {
		ampli.Instance.AnalysisIsTriggered(authenticatedUserId, event, eventOptions...)
	}
	c.enqueueEvent(captureFn)
}

func (c *Client) IssueHoverIsDisplayed(properties ux2.IssueHoverIsDisplayedProperties) {
	log.Info().Str("method", "IssueHoverIsDisplayed").Msg("analytics enqueued")
	ide := ampli.IssueHoverIsDisplayedIde(getIdeProperty())
	issueType := ampli.IssueHoverIsDisplayedIssueType(properties.IssueType)
	severity := ampli.IssueHoverIsDisplayedSeverity(properties.Severity)
	event := ampli.IssueHoverIsDisplayed.Builder().Ide(ide).IssueId(properties.IssueId).IssueType(issueType).Severity(severity).Build()

	captureFn := func(authenticatedUserId string, eventOptions ...ampli.EventOptions) {
		ampli.Instance.IssueHoverIsDisplayed(authenticatedUserId, event, eventOptions...)
	}
	c.enqueueEvent(captureFn)
}

func (c *Client) PluginIsInstalled(properties ux2.PluginIsInstalledProperties) {
	log.Info().Str("method", "PluginIsInstalled").Msg("analytics enqueued")
	ide := ampli.PluginIsInstalledIde(getIdeProperty())
	event := ampli.PluginIsInstalled.Builder().Ide(ide).Build()

	captureFn := func(_ string, eventOptions ...ampli.EventOptions) {
		ampli.Instance.PluginIsInstalled("", event, eventOptions...)
	}
	c.enqueueEvent(captureFn)
}

func (c *Client) enqueueEvent(eventFn captureEvent) {
	if config.CurrentConfig().IsTelemetryEnabled() {
		eventFn(
			c.authenticatedUserId,
			ampli.EventOptions{
				DeviceID: config.CurrentConfig().DeviceID(),
			})
	}
}

func (c *Client) Identify() {
	method := "infrastructure.segment.client"
	log.Info().Str("method", method).Msg("Identifying a user.")
	if !config.CurrentConfig().NonEmptyToken() {
		c.authenticatedUserId = ""
		return
	}

	user, err := c.snykApiClient.GetActiveUser()
	if err != nil {
		log.
			Warn().
			Err(errors.Wrap(err, "could not retrieve active user from API")).
			Str("method", method).Msg("using deviceId instead of user id")
		return
	}

	c.authenticatedUserId = user.Id

	if !config.CurrentConfig().IsTelemetryEnabled() {
		return
	}

	identifyEvent := ampli.Identify.Builder().UserId(user.Id).Build()
	ampli.Instance.Identify(c.authenticatedUserId, identifyEvent, ampli.EventOptions{})
}

// Only return an IDE property if it's a recognized IDE in the tracking plan
func getIdeProperty() ux2.IDE {
	// Standardize the names
	integrationName := strings.Replace(strings.ToLower(config.CurrentConfig().IntegrationName()), "_", " ", -1)

	switch integrationName {
	case strings.ToLower(string(ux2.Eclipse)):
		return ux2.Eclipse
	case strings.ToLower(string(ux2.VisualStudioCode)):
		return ux2.VisualStudioCode
	case strings.ToLower(string(ux2.VisualStudio)):
		return ux2.VisualStudio
	case strings.ToLower(string(ux2.JetBrains)):
		return ux2.JetBrains
	default:
		return "" // todo: will this pass Amplitude runtime validation?
	}
}

type segmentLogger struct{}

func (s *segmentLogger) Logf(format string, args ...interface{}) {
	log.Debug().Msgf(format, args...)
}

func (s *segmentLogger) Errorf(format string, args ...interface{}) {
	log.Error().Msgf(format, args...)
}
