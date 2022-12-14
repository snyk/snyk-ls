package amplitude

import (
	"sync"
	"testing"

	"github.com/amplitude/analytics-go/amplitude"
	"github.com/segmentio/analytics-go"
	segment "github.com/segmentio/analytics-go"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
)

func TestExecute_CapturesUserId(t *testing.T) {
	plugin, segmentClient := setupPlugin()
	e := &amplitude.Event{
		UserID: "myUserId",
	}

	plugin.Execute(e)

	equal := assert.ObjectsAreEqual(
		segment.Track{
			UserId:      "myUserId",
			AnonymousId: config.CurrentConfig().DeviceID(),
		},
		segmentClient.trackedEvents[0])
	assert.True(t, equal)
}

func TestExecute_CallsIdentify(t *testing.T) {
	plugin, segmentClient := setupPlugin()
	e := &amplitude.Event{
		UserID:    "authenticatedUserId",
		EventType: amplitude.IdentifyEventType,
	}

	plugin.Execute(e)

	equal := assert.ObjectsAreEqual(
		analytics.Identify{
			UserId:      "authenticatedUserId",
			AnonymousId: config.CurrentConfig().DeviceID(),
		},
		segmentClient.trackedEvents[0])
	assert.True(t, equal)
}

func setupPlugin() (*SegmentPlugin, *FakeSegmentClient) {
	plugin := NewSegmentPlugin()
	fakeSegmentClient := &FakeSegmentClient{mutex: &sync.Mutex{}}
	plugin.client = fakeSegmentClient
	return plugin, fakeSegmentClient
}
