package segment

import (
	"encoding/json"

	"github.com/rs/zerolog/log"
	segment "github.com/segmentio/analytics-go"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/internal/observability/user_behaviour"
)

type Client struct {
	userId  string
	IDE     user_behaviour.IDE
	segment segment.Client
}

func NewSegmentClient(userId string, IDE user_behaviour.IDE) user_behaviour.Analytics {
	segmentClient := &Client{
		userId:  userId,
		IDE:     IDE,
		segment: segment.New(getSegmentPublicKey()),
	}
	return segmentClient
}

func getSegmentPublicKey() string {
	if config.IsDevelopment() {
		return developmentPublicKey
	} else {
		return productionPublicKey
	}
}

func NewNoopClient() user_behaviour.Analytics {
	return &noopClient{}
}

func (s *Client) Close() error {
	return s.segment.Close()
}

func (s *Client) AnalysisIsReady(properties user_behaviour.AnalysisIsReadyProperties) {
	s.enqueueEvent(properties, "Analysis Is Ready")
}

func (s *Client) AnalysisIsTriggered(properties user_behaviour.AnalysisIsTriggeredProperties) {
	s.enqueueEvent(properties, "Analysis Is Triggered")
}

func (s *Client) IssueHoverIsDisplayed(properties user_behaviour.IssueHoverIsDisplayedProperties) {
	s.enqueueEvent(properties, "Issue Hover Is Displayed")
}

func (s *Client) PluginIsUninstalled(properties user_behaviour.PluginIsUninstalledProperties) {
	s.enqueueEvent(properties, "Plugin Is Uninstalled")
}

func (s *Client) PluginIsInstalled(properties user_behaviour.PluginIsInstalledProperties) {
	s.enqueueEvent(properties, "Plugin Is Installed")
}

func (s *Client) enqueueEvent(properties interface{}, event string) {
	err := s.segment.Enqueue(segment.Track{
		UserId:     s.userId,
		Event:      event,
		Properties: s.getSerialisedProperties(properties),
	})
	if err != nil {
		log.Warn().Err(err).Msg("Couldn't enqueue analytics")
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

type noopClient struct {
}

func (n noopClient) AnalysisIsReady(properties user_behaviour.AnalysisIsReadyProperties) {
}

func (n noopClient) AnalysisIsTriggered(properties user_behaviour.AnalysisIsTriggeredProperties) {
}

func (n noopClient) IssueHoverIsDisplayed(properties user_behaviour.IssueHoverIsDisplayedProperties) {
}

func (n noopClient) PluginIsUninstalled(properties user_behaviour.PluginIsUninstalledProperties) {
}

func (n noopClient) PluginIsInstalled(properties user_behaviour.PluginIsInstalledProperties) {
}
