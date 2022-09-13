package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/application/server"
)

func main() {
	defer func() {
		if err := recover(); err != nil {
			fmt.Println("🚨 Panicking 🚨")
			fmt.Println(err)
			debug.PrintStack()
			di.ErrorReporter().CaptureError(fmt.Errorf("%v", err))
			di.ErrorReporter().FlushErrorReporting()
		}
	}()

	output, err := parseFlags(os.Args)
	if err != nil {
		fmt.Println(err, output)
		os.Exit(1)
	}
	lines := strings.Split(config.LicenseInformation, " ")
	fmt.Println("License information")
	fmt.Println("Snyk Language Server is licensed under the Apache 2.0 license")
	fmt.Println("The following dependencies and licenses are used in this project:")
	for _, line := range lines {
		fmt.Println(line)
	}
	fmt.Println("You can access the detailed license information under https://github.com/snyk/snyk-ls/licenses")
	log.Info().Msg(config.Version)
	log.Trace().Interface("environment", os.Environ()).Msg("start environment")
	server.Start()
}

func parseFlags(args []string) (string, error) {
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	var buf bytes.Buffer
	flags.SetOutput(&buf)

	logLevelFlag := flags.String("l", "info", "sets the log-level to <trace|debug|info|warn|error|fatal>")
	logPathFlag := flags.String("f", "", "sets the log file for the language server")
	formatFlag := flags.String(
		"o",
		config.FormatMd,
		"sets format of diagnostics. Accepted values \""+config.FormatMd+"\" and \""+config.FormatHtml+"\"")
	configFlag := flags.String(
		"c",
		"",
		"provide the full path of a config file to use. format VARIABLENAME=VARIABLEVALUE")
	reportErrorsFlag := flags.Bool(
		"reportErrors",
		false,
		"enables error reporting")

	licensesFlag := flags.Bool(
		"licenses",
		false,
		"displays license information")

	err := flags.Parse(args[1:])
	if err != nil {
		return buf.String(), err
	}

	if *licensesFlag {
		buf.Write([]byte(config.LicenseInformation))
	}

	c := config.New()
	c.SetConfigFile(*configFlag)
	c.Load()

	c.SetLogPath(*logPathFlag)
	c.ConfigureLogging(*logLevelFlag)

	c.SetFormat(*formatFlag)
	if os.Getenv(config.SendErrorReportsKey) == "" {
		c.SetErrorReportingEnabled(*reportErrorsFlag)
	}

	config.SetCurrentConfig(c)
	return buf.String(), nil
}
