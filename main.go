package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"

	"github.com/adrg/xdg"
	"github.com/rs/zerolog/log"

	config2 "github.com/snyk/snyk-ls/application/config"
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

	// these directories are searched to find binaries (e.g. java, maven, etc)
	defaultDirs := []string{
		filepath.Join(xdg.Home, ".sdkman"),
		"/usr/lib",
		"/usr/java",
		"/opt",
		"/Library",
		"C:\\Program Files",
		"C:\\Program Files (x86)",
	}
	output, err := parseFlags(os.Args, defaultDirs)
	if err != nil {
		fmt.Println(err, output)
		os.Exit(1)
	}
	log.Info().Msg(config2.Version)
	log.Trace().Interface("environment", os.Environ()).Msg("start environment")
	server.Start()
}

func parseFlags(args []string, defaultDirs []string) (string, error) {
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	var buf bytes.Buffer
	flags.SetOutput(&buf)

	logLevelFlag := flags.String("l", "info", "sets the log-level to <trace|debug|info|warn|error|fatal>")
	logPathFlag := flags.String("f", "", "sets the log file for the language server")
	formatFlag := flags.String(
		"o",
		config2.FormatMd,
		"sets format of diagnostics. Accepted values \""+config2.FormatMd+"\" and \""+config2.FormatHtml+"\"")
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

	c := config2.New(defaultDirs)
	c.SetConfigFile(*configFlag)
	c.Load()

	c.SetLogPath(*logPathFlag)
	c.ConfigureLogging(*logLevelFlag)

	c.SetFormat(*formatFlag)
	if os.Getenv(config2.SendErrorReportsKey) == "" {
		c.SetErrorReportingEnabled(*reportErrorsFlag)
	}

	config2.SetCurrentConfig(c)
	return buf.String(), nil
}
