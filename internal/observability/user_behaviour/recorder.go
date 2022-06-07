package user_behaviour

import "github.com/rs/zerolog/log"

func NewNoopRecordingClient() Analytics {
	return &AnalyticsRecorder{}
}

type AnalyticsRecorder struct {
	Analytics []interface{}
}

func (n *AnalyticsRecorder) AnalysisIsReady(properties AnalysisIsReadyProperties) {
	n.Analytics = append(n.Analytics, properties)
	log.Info().Str("method", "AnalysisIsReady").Msg("no op")
}

func (n *AnalyticsRecorder) AnalysisIsTriggered(properties AnalysisIsTriggeredProperties) {
	n.Analytics = append(n.Analytics, properties)
	log.Info().Str("method", "AnalysisIsTriggered").Msg("no op")
}

func (n *AnalyticsRecorder) IssueHoverIsDisplayed(properties IssueHoverIsDisplayedProperties) {
	n.Analytics = append(n.Analytics, properties)
	log.Info().Str("method", "IssueHoverIsDisplayed").Msg("no op")
}

func (n *AnalyticsRecorder) PluginIsUninstalled(properties PluginIsUninstalledProperties) {
	n.Analytics = append(n.Analytics, properties)
	log.Info().Str("method", "PluginIsUninstalled").Msg("no op")
}

func (n *AnalyticsRecorder) PluginIsInstalled(properties PluginIsInstalledProperties) {
	n.Analytics = append(n.Analytics, properties)
	log.Info().Str("method", "PluginIsInstalled").Msg("no op")
}
