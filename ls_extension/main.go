/*
 * © 2023 Snyk Limited All rights reserved.
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

package ls_extension

import (
	"context"
	"fmt"
	"os"

	"github.com/snyk/snyk-ls/application/entrypoint"
	"github.com/snyk/snyk-ls/application/server"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/infrastructure/cli/cli_constants"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"

	"github.com/snyk/snyk-ls/application/config"
)

var WORKFLOWID_LS workflow.Identifier = workflow.NewWorkflowIdentifier("language-server")

func Init(engine workflow.Engine) error {

	flags := pflag.NewFlagSet("language-server", pflag.ContinueOnError)
	flags.BoolP("v", "v", false, "prints the version")
	flags.BoolP("protocolVersionFlag", "p", false, "prints the Snyk ls protocol version used to sync client and server")
	flags.StringP("logLevelFlag", "l", "info", "sets the log-level to <trace|debug|info|warn|error|fatal>")
	flags.StringP("logPathFlag", "f", "", "sets the log file for the language server")
	flags.StringP(
		"formatFlag",
		"o",
		config.FormatMd,
		"sets format of diagnostics. Accepted values \""+config.FormatMd+"\" and \""+config.FormatHtml+"\"")
	flags.StringP(
		"configfile",
		"c",
		"",
		"provide the full path of a config file to use. format VARIABLENAME=VARIABLEVALUE")
	flags.Bool(
		"licenses",
		false,
		"displays license information")

	flagsetConfig := workflow.ConfigurationOptionsFromFlagset(flags)
	entry, _ := engine.Register(WORKFLOWID_LS, flagsetConfig, lsWorkflow)
	entry.SetVisibility(false)

	return nil
}

func lsWorkflow(
	invocation workflow.InvocationContext,
	_ []workflow.Data,
) (output []workflow.Data, err error) {
	defer entrypoint.OnPanicRecover()

	output = []workflow.Data{}

	logger := invocation.GetEnhancedLogger()
	extensionConfig := invocation.GetConfiguration()

	logger.Info().Msgf("LS Version: %s", config.Version)
	logger.Info().Msgf("LS Protocol Version: %s", config.LsProtocolVersion)

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	c := config.CurrentConfig()
	c.SetConfigFile(extensionConfig.GetString("configfile"))
	c.Load()
	c.SetLogLevel(extensionConfig.GetString("logLevelFlag"))
	c.SetLogPath(extensionConfig.GetString("logPathFlag"))
	c.SetFormat(extensionConfig.GetString("formatFlag"))

	defaultConfig := c.Engine().GetConfiguration()
	defaultConfig.Set(cli_constants.EXECUTION_MODE_KEY, cli_constants.EXECUTION_MODE_VALUE_EXTENSION)
	c.SetEngine(invocation.GetEngine())
	c.Engine().SetConfiguration(defaultConfig)

	if extensionConfig.GetBool("v") {
		fmt.Println(config.Version)
		return output, err

	} else if extensionConfig.GetBool("licenses") {
		about, err := cli.NewExtensionExecutor().Execute(context.Background(), []string{"snyk", "--about"}, "")
		fmt.Println(string(about))
		return output, err

	} else if extensionConfig.GetBool("protocolVersionFlag") {
		fmt.Println(config.LsProtocolVersion)
		return output, err
	} else {
		logger.Trace().Interface("environment", os.Environ()).Msg("start environment")
		server.Start(c)
	}

	return output, nil
}
