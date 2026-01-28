/*
 * © 2026 Snyk Limited All rights reserved.
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
	"fmt"

	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/infrastructure/diagnostics/directory_check"
)

var WORKFLOWID_IDE_DIRECTORY_CHECK = workflow.NewWorkflowIdentifier("tools.ide-directory-check")

func initToolsIDEDirectoryCheck(engine workflow.Engine) error {
	flags := pflag.NewFlagSet("tools.ide-directory-check", pflag.ContinueOnError)
	flags.Bool("json", false, "Output in JSON format")
	flags.Bool("no-color", false, "Disable colored output")

	cfg := workflow.ConfigurationOptionsFromFlagset(flags)
	_, err := engine.Register(WORKFLOWID_IDE_DIRECTORY_CHECK, cfg, ideDirectoryCheckWorkflow)
	return err
}

func ideDirectoryCheckWorkflow(
	invocation workflow.InvocationContext,
	_ []workflow.Data,
) (output []workflow.Data, err error) {
	output = []workflow.Data{}

	cfg := invocation.GetConfiguration()
	jsonOutput := cfg.GetBool("json")
	noColor := cfg.GetBool("no-color")
	logger := invocation.GetEnhancedLogger()

	// Run directory diagnostics
	result := directory_check.RunDiagnostics(logger, nil)

	// Format output based on flags
	var formattedOutput string
	var contentType string

	if jsonOutput {
		formattedOutput, err = directory_check.FormatResultsJSON(result)
		if err != nil {
			return nil, fmt.Errorf("failed to format results as JSON: %w", err)
		}
		contentType = "application/json"
	} else {
		useColor := !noColor
		formattedOutput = directory_check.FormatResultsText(result, useColor)
		contentType = "text/plain"
	}

	data := workflow.NewData(
		workflow.NewTypeIdentifier(WORKFLOWID_IDE_DIRECTORY_CHECK, "output"),
		contentType,
		[]byte(formattedOutput),
	)
	output = append(output, data)

	return output, nil
}
