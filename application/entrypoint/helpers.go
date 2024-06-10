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
		fmt.Println("🚨 Panicking 🚨")
		fmt.Println(err)
		debug.PrintStack()
		er := sentry.NewSentryErrorReporter(config.CurrentConfig(), nil)
		er.CaptureError(fmt.Errorf("%v", err))
		er.FlushErrorReporting()
	}
}

func PrintLicenseText(output string) {
	fmt.Fprintln(os.Stderr, "License information")
	fmt.Fprintln(os.Stderr, "Snyk Language Server is licensed under the Apache 2.0 license")
	fmt.Fprintln(os.Stderr, "The following dependencies and licenses are used in this project:")
	fmt.Fprintln(os.Stderr, strings.ReplaceAll(output, " ", "\n"))
	fmt.Fprintln(os.Stderr,
		"You can access the detailed license information under https://github.com/snyk/snyk-ls/tree/main/licenses")
}
