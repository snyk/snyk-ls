package ux

import (
	"sync"

	"github.com/rs/zerolog/log"
)

func NewNoopRecordingClient() *AnalyticsRecorder {
	return &AnalyticsRecorder{}
}

type AnalyticsRecorder struct {
	analytics []interface{}
	mutex     sync.Mutex
}

func (n *AnalyticsRecorder) GetAnalytics() []interface{} {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	return n.analytics
}

func (n *AnalyticsRecorder) AnalysisIsReady(properties AnalysisIsReadyProperties) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.analytics = append(n.analytics, properties)
	log.Info().Str("method", "AnalysisIsReady").Msg("no op")
}

func (n *AnalyticsRecorder) AnalysisIsTriggered(properties AnalysisIsTriggeredProperties) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.analytics = append(n.analytics, properties)
	log.Info().Str("method", "AnalysisIsTriggered").Msg("no op")
}

func (n *AnalyticsRecorder) IssueHoverIsDisplayed(properties IssueHoverIsDisplayedProperties) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.analytics = append(n.analytics, properties)
	log.Info().Str("method", "IssueHoverIsDisplayed").Msg("no op")
}

func (n *AnalyticsRecorder) PluginIsUninstalled(properties PluginIsUninstalledProperties) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.analytics = append(n.analytics, properties)
	log.Info().Str("method", "PluginIsUninstalled").Msg("no op")
}

func (n *AnalyticsRecorder) PluginIsInstalled(properties PluginIsInstalledProperties) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.analytics = append(n.analytics, properties)
	log.Info().Str("method", "PluginIsInstalled").Msg("no op")
}
