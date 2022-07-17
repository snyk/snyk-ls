package segment

import (
	"encoding/json"

	"github.com/rs/zerolog/log"
	segment "github.com/segmentio/analytics-go"

	"github.com/snyk/snyk-ls/application/config"
	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
)

type Client struct {
	userId  string
	IDE     ux2.IDE
	segment segment.Client
}

// NewSegmentClient TODO use deviceID, e.g. hash of SNYK TOKEN if user is empty
// https://github.com/snyk/snyk-intellij-plugin/blob/d2f1ef7fd80acb84bfd8678efada324d12d6a246/src/main/kotlin/snyk/amplitude/api/AmplitudeExperimentApiClient.kt
// https://github.com/MatthewKing/DeviceId
func NewSegmentClient(userId string, IDE ux2.IDE) ux2.Analytics {
	client, err := segment.NewWithConfig(getSegmentPublicKey(), segment.Config{Logger: &segmentLogger{}})
	if err != nil {
		log.Error().Str("method", "NewSegmentClient").Err(err).Msg("Error creating segment client")
	}
	segmentClient := &Client{
		userId:  userId,
		IDE:     IDE,
		segment: client,
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

func (s *Client) Close() error {
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
			UserId:     s.userId,
			Event:      event,
			Properties: s.getSerialisedProperties(properties),
		})
		if err != nil {
			log.Warn().Err(err).Msg("Couldn't enqueue analytics")
		}
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
