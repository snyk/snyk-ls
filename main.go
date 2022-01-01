package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/snyk/snyk-lsp/server"
	"github.com/snyk/snyk-lsp/util"
	"log"
	"os"
	"time"
)

var gitinfo string // set by build via go build -ldflags "-X main.gitinfo=xxx"

func main() {
	fmt.Println(gitinfo)
	output, err := parseFlags(os.Args)
	if err != nil {
		fmt.Println(err, output)
		os.Exit(1)
	}
	util.Load()
	server.Start()
}

func parseFlags(args []string) (string, error) {
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	var buf bytes.Buffer
	flags.SetOutput(&buf)

	logLevelFlag := flags.String("l", "info", "sets the log-level to <trace|debug|info|warn|error|fatal>")
	formatFlag := flags.String(
		"o",
		util.FormatMd,
		"sets format of diagnostics. Accepted values \""+util.FormatMd+"\" and \""+util.FormatHtml+"\"")
	configFlag := flags.String(
		"c",
		"",
		"provide the full path of a config file to use. Format VARIABLENAME=VARIABLEVALUE")

	err := flags.Parse(args[1:])
	if err != nil {
		return buf.String(), err
	}

	configureLogging(*logLevelFlag)
	util.Format = *formatFlag
	util.ConfigFile = *configFlag
	return buf.String(), nil
}

func configureLogging(level string) {
	logLevel, err := zerolog.ParseLevel(level)
	if err != nil {
		log.Println("Can't set log level from flag. Setting to default (=info)")
		logLevel = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(logLevel)
	zerolog.TimeFieldFormat = time.RFC3339
}
