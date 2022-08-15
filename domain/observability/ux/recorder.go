package ux

import (
	"sync"

	"github.com/rs/zerolog/log"
)

func NewTestAnalytics() *TestAnalytics {
	return &TestAnalytics{}
}

type TestAnalytics struct {
	analytics  []interface{}
	mutex      sync.Mutex
	Identified bool
}

func (n *TestAnalytics) GetAnalytics() []interface{} {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	return n.analytics
}

func (n *TestAnalytics) AnalysisIsReady(properties AnalysisIsReadyProperties) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.analytics = append(n.analytics, properties)
	log.Info().Str("method", "AnalysisIsReady").Msgf("no op - args %v", properties)
}

func (n *TestAnalytics) AnalysisIsTriggered(properties AnalysisIsTriggeredProperties) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.analytics = append(n.analytics, properties)
	log.Info().Str("method", "AnalysisIsTriggered").Msgf("no op - args %v", properties)
}

func (n *TestAnalytics) IssueHoverIsDisplayed(properties IssueHoverIsDisplayedProperties) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.analytics = append(n.analytics, properties)
	log.Info().Str("method", "IssueHoverIsDisplayed").Msgf("no op - args %v", properties)
}

func (n *TestAnalytics) PluginIsUninstalled(properties PluginIsUninstalledProperties) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.analytics = append(n.analytics, properties)
	log.Info().Str("method", "PluginIsUninstalled").Msgf("no op - args %v", properties)
}

func (n *TestAnalytics) PluginIsInstalled(properties PluginIsInstalledProperties) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.analytics = append(n.analytics, properties)
	log.Info().Str("method", "PluginIsInstalled").Msgf("no op - args %v", properties)
}

func (n *TestAnalytics) Initialise() {
	log.Info().Str("method", "Init").Msgf("no op")
}
func (n *TestAnalytics) Shutdown() error {
	log.Info().Str("method", "Shutdown").Msgf("no op")
	return nil
}
func (n *TestAnalytics) Identify() {
	log.Info().Str("method", "Identify").Msgf("no op")
	n.Identified = true
}
