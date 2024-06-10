/*
 * © 2022 Snyk Limited All rights reserved.
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

package ux

import (
	"sync"

	"github.com/snyk/snyk-ls/application/config"
)

var _ Analytics = &TestAnalytics{} // Explicit interface implementation

func NewTestAnalytics(c *config.Config) *TestAnalytics {
	return &TestAnalytics{c: c}
}

type TestAnalytics struct {
	analytics               []any
	mutex                   sync.Mutex
	Identified              bool
	Initialized             bool
	ScanModeIsSelectedCount int
	c                       *config.Config
}

func (n *TestAnalytics) GetAnalytics() []any {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	return n.analytics
}

func (n *TestAnalytics) AnalysisIsReady(properties AnalysisIsReadyProperties) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.analytics = append(n.analytics, properties)
	n.c.Logger().Info().Str("method", "AnalysisIsReady").Msgf("no op - args %v", properties)
}

func (n *TestAnalytics) AnalysisIsTriggered(properties AnalysisIsTriggeredProperties) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.analytics = append(n.analytics, properties)
	n.c.Logger().Info().Str("method", "AnalysisIsTriggered").Msgf("no op - args %v", properties)
}

func (n *TestAnalytics) IssueHoverIsDisplayed(properties IssueHoverIsDisplayedProperties) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.analytics = append(n.analytics, properties)
	n.c.Logger().Info().Str("method", "IssueHoverIsDisplayed").Msgf("no op - args %v", properties)
}

func (n *TestAnalytics) PluginIsInstalled(properties PluginIsInstalledProperties) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.analytics = append(n.analytics, properties)
	n.c.Logger().Info().Str("method", "PluginIsInstalled").Msgf("no op - args %v", properties)
}

func (n *TestAnalytics) Initialise() { //nolint:misspell // breaking api change
	n.c.Logger().Info().Str("method", "Init").Msgf("no op")
	n.Initialized = true
}
func (n *TestAnalytics) Shutdown() error {
	n.c.Logger().Info().Str("method", "Shutdown").Msgf("no op")
	return nil
}
func (n *TestAnalytics) Identify() {
	n.c.Logger().Info().Str("method", "Identify").Msgf("no op")
	n.Identified = true
}

func (n *TestAnalytics) ScanModeIsSelected(properties ScanModeIsSelectedProperties) {
	n.c.Logger().Info().Str("method", "ScanModeIsSelected").Msgf("no op")
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.ScanModeIsSelectedCount++
}
