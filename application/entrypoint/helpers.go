package entrypoint

import (
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/sentry"
)

func OnPanicRecover() {
	if err := recover(); err != nil {
		panickingMsg := "🚨 Panicking 🚨"
		_, _ = fmt.Fprintln(os.Stderr, panickingMsg)
		_, _ = fmt.Fprintln(os.Stderr, err)
		debug.PrintStack()

		c := config.CurrentConfig()
		logger := c.Logger()

		logger.Error().Msg(panickingMsg)
		logger.Error().Any("recovered panic", err).Send()
		logger.Error().Msg(string(debug.Stack()))

		er := sentry.NewSentryErrorReporter(c, nil)
		er.CaptureError(fmt.Errorf("%v", err))
		er.FlushErrorReporting()
	}
}

func PrintLicenseText(output string) {
	_, _ = fmt.Fprintln(os.Stderr, "License information")
	_, _ = fmt.Fprintln(os.Stderr, "Snyk Language Server is licensed under the Apache 2.0 license")
	_, _ = fmt.Fprintln(os.Stderr, "The following dependencies and licenses are used in this project:")
	_, _ = fmt.Fprintln(os.Stderr, strings.ReplaceAll(output, " ", "\n"))
	_, _ = fmt.Fprintln(os.Stderr, "You can access the detailed license information under https://github.com/snyk/snyk-ls/tree/main/licenses")
}
