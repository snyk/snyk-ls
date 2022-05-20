package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/error_reporting"
	"github.com/snyk/snyk-ls/server"
)

func main() {
	defer func() {
		if err := recover(); err != nil {
			error_reporting.CaptureError(fmt.Errorf("%v", err))
			error_reporting.FlushErrorReporting()
		}
	}()
	output, err := parseFlags(os.Args)
	if err != nil {
		fmt.Println(err, output)
		os.Exit(1)
	}
	log.Info().Msg(config.Version)
	log.Trace().Interface("environment", os.Environ()).Msg("start environment")
	error_reporting.InitErrorReporting()
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

	err := flags.Parse(args[1:])
	if err != nil {
		return buf.String(), err
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
