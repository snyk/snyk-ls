package server

import (
	"context"

	"github.com/creachadair/jrpc2"
	"github.com/rs/zerolog/log"
)

func notifier(srv **jrpc2.Server, method string, params interface{}) {
	log.Debug().Str("method", "notifier").Msgf("Notifying")
	err := (*srv).Notify(context.Background(), method, params)
	logError(err, "notifier")
}
