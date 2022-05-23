package error_reporting

import (
	"fmt"
	"time"

	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/internal/notification"

	"github.com/getsentry/sentry-go"
	"github.com/rs/zerolog/log"
)

func FlushErrorReporting() {
	// Set the timeout to the maximum duration the program can afford to wait
	defer sentry.Flush(2 * time.Second)
}

func CaptureError(err error) bool {
	notification.Send(sglsp.ShowMessageParams{
		Type:    sglsp.MTError,
		Message: fmt.Sprintf("Snyk encountered an error: %v", err),
	})
	if config.CurrentConfig().IsErrorReportingEnabled() {
		log.Debug().Err(err).Str("method", "CaptureError").Msgf("Sending error to Sentry")
		sentry.CaptureException(err)
		return true
	}
	return false
}
