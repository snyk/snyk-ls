/*
 * © 2022 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/server"
	"github.com/snyk/snyk-ls/infrastructure/sentry"
)

func main() {
	defer func() {
		if err := recover(); err != nil {
			fmt.Println("🚨 Panicking 🚨")
			fmt.Println(err)
			debug.PrintStack()
			er := sentry.NewSentryErrorReporter(nil)
			er.CaptureError(fmt.Errorf("%v", err))
			er.FlushErrorReporting()
		}
	}()

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	c := config.CurrentConfig()
	output, err := parseFlags(os.Args, c)
	if err != nil {
		fmt.Println(err, output)
		os.Exit(1)
	}
	if output != "" {
		fmt.Fprintln(os.Stderr, "License information")
		fmt.Fprintln(os.Stderr, "Snyk Language Server is licensed under the Apache 2.0 license")
		fmt.Fprintln(os.Stderr, "The following dependencies and licenses are used in this project:")
		fmt.Fprintln(os.Stderr, strings.ReplaceAll(output, " ", "\n"))
		fmt.Fprintln(os.Stderr,
			"You can access the detailed license information under https://github.com/snyk/snyk-ls/tree/main/licenses")
	}

	log.Trace().Interface("environment", os.Environ()).Msg("start environment")
	server.Start(c)
}

func parseFlags(args []string, c *config.Config) (string, error) {
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	var buf bytes.Buffer
	flags.SetOutput(&buf)

	versionFlag := flags.Bool("v", false, "prints the version")
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

	if *versionFlag {
		return buf.String(), fmt.Errorf(config.Version)
	}

	if *licensesFlag {
		buf.Write([]byte(config.LicenseInformation))
	}

	c.SetConfigFile(*configFlag)
	c.Load()
	c.SetLogLevel(*logLevelFlag)
	c.SetLogPath(*logPathFlag)
	c.SetFormat(*formatFlag)
	if os.Getenv(config.SendErrorReportsKey) == "" {
		c.SetErrorReportingEnabled(*reportErrorsFlag)
	}

	config.SetCurrentConfig(c)
	return buf.String(), nil
}
