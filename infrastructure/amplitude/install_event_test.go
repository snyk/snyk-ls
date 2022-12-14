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

package amplitude

import (
	"os"
	"path/filepath"
	"testing"

	segment "github.com/segmentio/analytics-go"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/ampli"
	"github.com/snyk/snyk-ls/application/config"
)

var installEventFile = filepath.Join(config.CurrentConfig().CliSettings().DefaultBinaryInstallPath(), ".installed_event_sent")

func Test_NewInstallationCreatesStateFile(t *testing.T) {
	s, _, _ := setupUnitTest(t)
	cleanupInstallEventFile(t)

	s.captureInstalledEvent()

	_, err := os.Stat(installEventFile)
	assert.NoError(t, err)
}

func Test_NewInstallationSendsInstallEvent(t *testing.T) {
	s, fakeSegmentClient, _ := setupUnitTest(t)
	cleanupInstallEventFile(t)

	s.captureInstalledEvent()

	assert.Len(t, fakeSegmentClient.trackedEvents, 1)
	assert.Equal(t, segment.Track{
		UserId:      "",
		Event:       "Plugin Is Installed",
		AnonymousId: config.CurrentConfig().DeviceID(),
		Properties: segment.Properties{}.
			Set("ide", ampli.PluginIsInstalledIde("Visual Studio Code")).
			Set("itly", true),
	}, fakeSegmentClient.trackedEvents[0])
}

func Test_ExistingInstallationDoesntSendInstallEvent(t *testing.T) {
	s, fakeSegmentClient, _ := setupUnitTest(t)
	cleanupInstallEventFile(t)
	f, err := os.Create(installEventFile)
	if err != nil {
		t.Error("Failed to create install event file.")
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)

	s.captureInstalledEvent()

	assert.Len(t, fakeSegmentClient.trackedEvents, 0)
}

func cleanupInstallEventFile(t *testing.T) {
	err := os.Remove(installEventFile)
	if err != nil && !os.IsNotExist(err) {
		t.Error(err)
	}
}
