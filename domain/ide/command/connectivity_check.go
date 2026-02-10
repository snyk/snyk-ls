/*
 * © 2025 Snyk Limited
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

package command

import (
	"context"
	"errors"

	connectivityworkflow "github.com/snyk/go-application-framework/pkg/local_workflows/connectivity_check_extension"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
)

type connectivityCheckCommand struct {
	command types.CommandData
	c       *config.Config
}

func (cmd *connectivityCheckCommand) Command() types.CommandData {
	return cmd.command
}

func (cmd *connectivityCheckCommand) Execute(ctx context.Context) (any, error) {
	logger := cmd.c.Logger().With().Str("command", "connectivityCheck").Str("method", "Execute").Logger()
	engine := cmd.c.Engine()

	// Set configuration for connectivity check workflow
	// Default to formatted text output with no color
	gafConfig := engine.GetConfiguration().Clone()
	gafConfig.Set("json", false)
	gafConfig.Set("no-color", true)

	// Invoke the GAF workflow directly
	output, err := engine.InvokeWithConfig(connectivityworkflow.WORKFLOWID_CONNECTIVITY_CHECK, gafConfig)
	if err != nil {
		logger.Warn().Err(err).Msg("Connectivity check workflow returned an error")
		return "", err
	}

	if len(output) == 0 {
		logger.Warn().Msg("Connectivity check workflow returned no output")
		return "", errors.New("connectivity check workflow returned no output")
	}

	// Get the payload from the first workflow data item
	payload := output[0].GetPayload()
	if payload == nil {
		logger.Warn().Msg("Connectivity check workflow returned no payload")
		return "", errors.New("connectivity check workflow returned no payload")
	}

	// The payload should be a byte array containing the formatted output
	payloadBytes, ok := payload.([]byte)
	if !ok {
		logger.Warn().Msg("Unexpected payload type from connectivity check workflow")
		return "", errors.New("unexpected payload type from connectivity check workflow")
	}

	return string(payloadBytes), nil
}
