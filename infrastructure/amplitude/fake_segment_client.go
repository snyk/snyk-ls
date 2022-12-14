package amplitude

import (
	"sync"

	segment "github.com/segmentio/analytics-go"
)

type FakeSegmentClient struct {
	trackedEvents []segment.Message
	mutex         *sync.Mutex
}

func (f *FakeSegmentClient) Close() error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.trackedEvents = []segment.Message{}
	return nil
}

func (f *FakeSegmentClient) Enqueue(message segment.Message) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.trackedEvents = append(f.trackedEvents, message)
	return nil
}
