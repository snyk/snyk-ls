package notification

import (
	"fmt"

	sglsp "github.com/sourcegraph/go-lsp"
)

type Event string

var channel = make(chan interface{}, 100)
var stopChannel = make(chan bool, 1000)

func Send(msg interface{}) {
	channel <- msg
}

func SendError(err error) {
	Send(sglsp.ShowMessageParams{
		Type:    sglsp.MTError,
		Message: fmt.Sprintf("Snyk encountered an error: %v", err),
	})
}

func Receive() (payload interface{}, stop bool) {
	select {
	case payload = <-channel:
		return payload, false
	case <-stopChannel:
		return payload, true
	}
}

func CreateListener(callback func(params interface{})) {
	// cleanup stopchannel before starting
	for {
		select {
		case <-stopChannel:
			continue
		default:
			break
		}
		break
	}
	go func() {
		for {
			payload, stop := Receive()
			if stop {
				break
			}
			callback(payload)
		}
	}()
}

func DisposeListener() {
	stopChannel <- true
}
