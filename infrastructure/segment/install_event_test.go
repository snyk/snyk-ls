package segment

import (
	"os"
	"path/filepath"
	"testing"

	segment "github.com/segmentio/analytics-go"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
)

var installEventFile = filepath.Join(config.CurrentConfig().DefaultBinaryInstallPath(), ".installed_event_sent")

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
		AnonymousId: s.anonymousUserId,
		Properties: segment.Properties{}.
			Set("ide", ux2.IDE("Visual Studio Code")).
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
	defer f.Close()

	s.captureInstalledEvent()

	assert.Len(t, fakeSegmentClient.trackedEvents, 0)
}

func cleanupInstallEventFile(t *testing.T) {
	err := os.Remove(installEventFile)
	if err != nil && !os.IsNotExist(err) {
		t.Error(err)
	}
}
