package amplitude

import (
	"github.com/rs/zerolog/log"
	segment "github.com/segmentio/analytics-go"

	"github.com/snyk/snyk-ls/application/config"

	"github.com/amplitude/analytics-go/amplitude"
	"github.com/amplitude/analytics-go/amplitude/types"
)

// Segment plugin allows events delivery to Segment via Amplitude Data.
type SegmentPlugin struct {
	client segment.Client
}

func NewSegmentPlugin() *SegmentPlugin {
	return &SegmentPlugin{}
}

// Setup is called on plugin installation
func (plugin *SegmentPlugin) Setup(config amplitude.Config) {
	client, err := segment.NewWithConfig(getSegmentPublicKey(), segment.Config{Logger: &segmentLogger{}})
	if err != nil {
		log.Error().Str("method", "NewSegmentClient").Err(err).Msg("Error creating Segment client")
	}

	plugin.client = client
}

func (plugin SegmentPlugin) Name() string {
	return "SegmentPlugin"
}

func (plugin SegmentPlugin) Type() amplitude.PluginType {
	return amplitude.PluginTypeDestination
}

// Execute is called on each event instrumented
func (plugin *SegmentPlugin) Execute(event *amplitude.Event) {
	method := "infrastructure.segment.segment_plugin"
	userId := event.UserID
	if userId == "" {
		userId = event.EventOptions.UserID
	}

	if event.EventType == amplitude.IdentifyEventType {
		plugin.identify(userId, method)
		return
	}

	plugin.track(userId, event, method)
}

func (plugin *SegmentPlugin) track(userId string, event *types.Event, method string) {
	err := plugin.client.Enqueue(segment.Track{
		UserId:      userId,
		Event:       event.EventType,
		Properties:  event.EventProperties,
		AnonymousId: config.CurrentConfig().DeviceID(),
	})
	if err != nil {
		log.Warn().Err(err).Str("method", method).Msg("Couldn't enqueue tracking event.")
	}
}

func (plugin *SegmentPlugin) identify(userId string, method string) {
	err := plugin.client.Enqueue(segment.Identify{
		AnonymousId: config.CurrentConfig().DeviceID(),
		UserId:      userId,
	})
	if err != nil {
		log.Warn().Err(err).Str("method", method).Msg("Couldn't enqueue identify message.")
	}
}

func (plugin *SegmentPlugin) Shutdown() error {
	return plugin.client.Close()
}

func getSegmentPublicKey() string {
	if config.IsDevelopment() {
		log.Info().Str("method", "getSegmentPublicKey").Msg("Configured segment client with dev key")
		return developmentPublicKey
	} else {
		log.Info().Str("method", "getSegmentPublicKey").Msg("Configured segment client with prod key")
		return productionPublicKey
	}
}
