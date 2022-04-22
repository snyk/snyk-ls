package notification

import (
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/lsp"
)

type Event string

var channel = make(chan lsp.AuthenticationParams, 100)
var stopChannel = make(chan bool, 1)

func CleanChannels() {
	channel = make(chan lsp.AuthenticationParams, 100)
	stopChannel = make(chan bool, 1)
}

func Send(token string) {
	channel <- lsp.AuthenticationParams{Token: token}
}

func Receive() (params lsp.AuthenticationParams, stopped bool) {
	select {
	case params = <-channel:
		log.Debug().Msgf("DEBUG: read %v", params)
		return params, false
	case stopped = <-stopChannel:
		log.Debug().Msgf("DEBUG: read %v", stopped)
		return params, stopped
	}
}

func CreateListener(callback func(params lsp.AuthenticationParams)) {
	go func() {
		log.Debug().Msg("Starting Auth Listener")
		defer log.Debug().Msg("Stopped Auth Listener")
		for {
			param, stopped := Receive()
			if stopped {
				break
			}
			callback(param)
		}
	}()
}

func DisposeListener() {
	stopChannel <- true
}
