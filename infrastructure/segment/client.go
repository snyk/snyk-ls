package segment

import (
	"encoding/json"

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
	anonymousUserId     string
	IDE                 ux2.IDE
	segment             segment.Client
	snykApiClient       snyk_api.SnykApiClient
	errorReporter       error_reporting.ErrorReporter
}

func NewSegmentClient(snykApiClient snyk_api.SnykApiClient, IDE ux2.IDE, errorReporter error_reporting.ErrorReporter) ux2.Analytics {
	client, err := segment.NewWithConfig(getSegmentPublicKey(), segment.Config{Logger: &segmentLogger{}})
	if err != nil {
		log.Error().Str("method", "NewSegmentClient").Err(err).Msg("Error creating segment client")
	}
	segmentClient := &Client{
		IDE:             IDE,
		segment:         client,
		snykApiClient:   snykApiClient,
		errorReporter:   errorReporter,
		anonymousUserId: config.CurrentConfig().DeviceID(),
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
			AnonymousId: s.anonymousUserId,
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
		AnonymousId: s.anonymousUserId,
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

	set := segment.NewProperties().
		Set("itly", true).
		Set("ide", s.IDE)

	for element := range result {
		set = set.Set(element, result[element])
	}

	return set
}

type segmentLogger struct{}

func (s *segmentLogger) Logf(format string, args ...interface{}) {
	log.Debug().Msgf(format, args...)
}

func (s *segmentLogger) Errorf(format string, args ...interface{}) {
	log.Error().Msgf(format, args...)
}
