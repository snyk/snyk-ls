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
	log.Info().Str("method", "AnalysisIsReady").Msgf("no op - args %v", properties)
}

func (n *AnalyticsRecorder) AnalysisIsTriggered(properties AnalysisIsTriggeredProperties) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.analytics = append(n.analytics, properties)
	log.Info().Str("method", "AnalysisIsTriggered").Msgf("no op - args %v", properties)
}

func (n *AnalyticsRecorder) IssueHoverIsDisplayed(properties IssueHoverIsDisplayedProperties) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.analytics = append(n.analytics, properties)
	log.Info().Str("method", "IssueHoverIsDisplayed").Msgf("no op - args %v", properties)
}

func (n *AnalyticsRecorder) PluginIsUninstalled(properties PluginIsUninstalledProperties) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.analytics = append(n.analytics, properties)
	log.Info().Str("method", "PluginIsUninstalled").Msgf("no op - args %v", properties)
}

func (n *AnalyticsRecorder) PluginIsInstalled(properties PluginIsInstalledProperties) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.analytics = append(n.analytics, properties)
	log.Info().Str("method", "PluginIsInstalled").Msgf("no op - args %v", properties)
}
