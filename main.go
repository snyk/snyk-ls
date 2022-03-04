package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/error_reporting"
	"github.com/snyk/snyk-ls/server"
)

func main() {
	output, err := parseFlags(os.Args)
	if err != nil {
		fmt.Println(err, output)
		os.Exit(1)
	}
	log.Info().Msg(config.Version)
	error_reporting.InitErrorReporting()
	environment.Load()
	server.Start()
}

func parseFlags(args []string) (string, error) {
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	var buf bytes.Buffer
	flags.SetOutput(&buf)

	logLevelFlag := flags.String("l", "info", "sets the log-level to <trace|debug|info|warn|error|fatal>")
	formatFlag := flags.String(
		"o",
		environment.FormatMd,
		"sets format of diagnostics. Accepted values \""+environment.FormatMd+"\" and \""+environment.FormatHtml+"\"")
	configFlag := flags.String(
		"c",
		"",
		"provide the full path of a config file to use. Format VARIABLENAME=VARIABLEVALUE")
	reportErrorsFlag := flags.Bool(
		"reportErrors",
		false,
		"enables error reporting")

	err := flags.Parse(args[1:])
	if err != nil {
		return buf.String(), err
	}

	configureLogging(*logLevelFlag)
	environment.Format = *formatFlag
	environment.ConfigFile = *configFlag
	config.IsErrorReportingEnabled = *reportErrorsFlag
	return buf.String(), nil
}

func configureLogging(level string) {
	logLevel, err := zerolog.ParseLevel(level)
	if err != nil {
		fmt.Println("Can't set log level from flag. Setting to default (=info)")
		logLevel = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(logLevel)
	zerolog.TimeFieldFormat = time.RFC3339
}
