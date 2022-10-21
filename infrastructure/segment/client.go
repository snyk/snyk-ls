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
	"encoding/json"
	"strings"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"github.com/segmentio/analytics-go"
	segment "github.com/segmentio/analytics-go"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
)

type Client struct {
	authenticatedUserId string
	segment             segment.Client
	snykApiClient       snyk_api.SnykApiClient
	errorReporter       error_reporting.ErrorReporter
}

func NewSegmentClient(snykApiClient snyk_api.SnykApiClient, errorReporter error_reporting.ErrorReporter) ux2.Analytics {
	client, err := segment.NewWithConfig(getSegmentPublicKey(), segment.Config{Logger: &segmentLogger{}})
	if err != nil {
		log.Error().Str("method", "NewSegmentClient").Err(err).Msg("Error creating segment client")
	}
	segmentClient := &Client{
		segment:       client,
		snykApiClient: snykApiClient,
		errorReporter: errorReporter,
	}

	return segmentClient
}

func getSegmentPublicKey() string {
	if config.IsDevelopment() {
		log.Info().Str("method", "getSegmentPublicKey").Msg("Configured segment client with dev key")
		return developmentPublicKey
	} else {
		log.Info().Str("method", "getSegmentPublicKey").Msg("Configured segment client with prod key")
		return productionPublicKey
	}
}

func (s *Client) Initialise() {
	go s.captureInstalledEvent()
}

func (s *Client) Shutdown() error {
	return s.segment.Close()
}

func (s *Client) AnalysisIsReady(properties ux2.AnalysisIsReadyProperties) {
	log.Info().Str("method", "AnalysisIsReady").Msg("analytics enqueued")
	s.enqueueEvent(properties, "Analysis Is Ready")
}

func (s *Client) AnalysisIsTriggered(properties ux2.AnalysisIsTriggeredProperties) {
	log.Info().Str("method", "AnalysisIsTriggered").Msg("analytics enqueued")
	s.enqueueEvent(properties, "Analysis Is Triggered")
}

func (s *Client) IssueHoverIsDisplayed(properties ux2.IssueHoverIsDisplayedProperties) {
	log.Info().Str("method", "IssueHoverIsDisplayed").Msg("analytics enqueued")
	s.enqueueEvent(properties, "Issue Hover Is Displayed")
}

func (s *Client) PluginIsUninstalled(properties ux2.PluginIsUninstalledProperties) {
	log.Info().Str("method", "PluginIsUninstalled").Msg("analytics enqueued")
	s.enqueueEvent(properties, "Plugin Is Uninstalled")
}

func (s *Client) PluginIsInstalled(properties ux2.PluginIsInstalledProperties) {
	log.Info().Str("method", "PluginIsInstalled").Msg("analytics enqueued")
	s.enqueueEvent(properties, "Plugin Is Installed")
}

func (s *Client) enqueueEvent(properties interface{}, event string) {
	if config.CurrentConfig().IsTelemetryEnabled() {
		err := s.segment.Enqueue(segment.Track{
			UserId:      s.authenticatedUserId,
			Event:       event,
			Properties:  s.getSerialisedProperties(properties),
			AnonymousId: config.CurrentConfig().DeviceID(),
		})
		if err != nil {
			log.Warn().Err(err).Msg("Couldn't enqueue analytics")
		}
	}
}

func (s *Client) Identify() {
	method := "infrastructure.segment.client"
	log.Info().Str("method", method).Msg("Identifying a user.")
	if !config.CurrentConfig().Authenticated() {
		s.authenticatedUserId = ""
		return
	}

	user, err := s.snykApiClient.GetActiveUser()
	if err != nil {
		log.
			Warn().
			Err(errors.Wrap(err, "could not retrieve active user from API")).
			Str("method", method).Msg("using deviceId instead of user id")
		return
	}

	s.authenticatedUserId = user.Id

	if !config.CurrentConfig().IsTelemetryEnabled() {
		return
	}

	err = s.segment.Enqueue(analytics.Identify{
		AnonymousId: config.CurrentConfig().DeviceID(),
		UserId:      s.authenticatedUserId,
	})
	if err != nil {
		log.Warn().Err(err).Str("method", method).Msg("Couldn't enqueue identify message.")
	}
}

func (s *Client) getSerialisedProperties(props interface{}) segment.Properties {
	marshal, err := json.Marshal(props)
	if err != nil {
		return nil
	}
	var result map[string]interface{}
	err = json.Unmarshal(marshal, &result)
	if err != nil {
		return nil
	}

	properties := segment.NewProperties().Set("itly", true)
	if ideProperty := getIdeProperty(); ideProperty != "" {
		properties.Set("ide", ideProperty)
	}

	for element := range result {
		properties = properties.Set(element, result[element])
	}

	return properties
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
		return ""
	}
}

type segmentLogger struct{}

func (s *segmentLogger) Logf(format string, args ...interface{}) {
	log.Debug().Msgf(format, args...)
}

func (s *segmentLogger) Errorf(format string, args ...interface{}) {
	log.Error().Msgf(format, args...)
}
