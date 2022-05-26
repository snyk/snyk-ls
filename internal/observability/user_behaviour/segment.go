package user_behaviour

import (
	"encoding/json"

	"github.com/rs/zerolog/log"
	segment "github.com/segmentio/analytics-go"
)

type SegmentClient struct {
	userId  string
	IDE     IDE
	segment segment.Client
}

func NewSegmentClient(writeKey string, userId string, IDE IDE) Analytics {
	segmentClient := &SegmentClient{
		userId:  userId,
		IDE:     IDE,
		segment: segment.New(writeKey),
	}
	return segmentClient
}

func (s *SegmentClient) Close() error {
	return s.segment.Close()
}

func (s *SegmentClient) AnalysisIsReady(properties AnalysisIsReadyProperties) {
	s.enqueueEvent(properties, "Analysis Is Ready")
}

func (s *SegmentClient) AnalysisIsTriggered(properties AnalysisIsTriggeredProperties) {
	s.enqueueEvent(properties, "Analysis Is Triggered")
}

func (s *SegmentClient) IssueHoverIsDisplayed(properties IssueHoverIsDisplayedProperties) {
	s.enqueueEvent(properties, "Issue Hover Is Displayed")
}

func (s *SegmentClient) PluginIsUninstalled(properties PluginIsUninstalledProperties) {
	s.enqueueEvent(properties, "Plugin Is Uninstalled")
}

func (s *SegmentClient) PluginIsInstalled(properties PluginIsInstalledProperties) {
	s.enqueueEvent(properties, "Plugin Is Installed")
}

func (s *SegmentClient) enqueueEvent(properties interface{}, event string) {
	err := s.segment.Enqueue(segment.Track{
		UserId:     s.userId,
		Event:      event,
		Properties: s.getSerialisedProperties(properties),
	})
	if err != nil {
		log.Warn().Err(err).Msg("Couldn't enqueue analytics")
	}
}

func (s *SegmentClient) getSerialisedProperties(props interface{}) segment.Properties {
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

	for element, _ := range result {
		set = set.Set(element, result[element])
	}

	return set
}
