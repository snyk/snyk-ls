/*
 * © 2023 Snyk Limited
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

package analytics

import (
	configuration2 "github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
)

func SendAnalyticsToAPI(c *config.Config, payload []byte) error {
	logger := c.Logger().With().Str("method", "analytics.sendAnalyticsToAPI").Logger()
	logger.Debug().Str("payload", string(payload)).Msg("Analytics Payload")

	inputData := workflow.NewData(
		workflow.NewTypeIdentifier(localworkflows.WORKFLOWID_REPORT_ANALYTICS, "reportAnalytics"),
		"application/json",
		payload,
	)

	engine := c.Engine()
	configuration := engine.GetConfiguration().Clone()
	configuration.Set(configuration2.FLAG_EXPERIMENTAL, true)

	_, err := engine.InvokeWithInputAndConfig(
		localworkflows.WORKFLOWID_REPORT_ANALYTICS,
		[]workflow.Data{inputData},
		configuration,
	)

	if err != nil {
		logger.Err(err).Msg("error invoking workflow")
		return err
	}
	return nil
}
