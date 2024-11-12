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
	"encoding/json"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/analytics"
	configuration2 "github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/instrumentation"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

var analyticsMu = sync.RWMutex{}

func SendAnalyticsToAPI(c *config.Config, payload []byte) error {
	logger := c.Logger().With().Str("method", "analytics.sendAnalyticsToAPI").Logger()

	var eventsParam types.AnalyticsEventParam
	err := json.Unmarshal(payload, &eventsParam)
	var inputData workflow.Data
	if err == nil && eventsParam.TimestampMs > 0 {
		ic := PayloadForAnalyticsEventParam(c, eventsParam)
		instrumentationObject, icErr := analytics.GetV2InstrumentationObject(ic)
		if icErr != nil {
			return err
		}

		bytes, marshalErr := json.Marshal(instrumentationObject)
		if marshalErr != nil {
			return marshalErr
		}

		logger.Debug().Str("payload", string(bytes)).Msg("Analytics Payload")
		inputData = workflow.NewData(
			workflow.NewTypeIdentifier(localworkflows.WORKFLOWID_REPORT_ANALYTICS, "reportAnalytics"),
			"application/json",
			bytes,
		)
	} else {
		logger.Debug().Str("payload", string(payload)).Msg("Analytics Payload")
		inputData = workflow.NewData(
			workflow.NewTypeIdentifier(localworkflows.WORKFLOWID_REPORT_ANALYTICS, "reportAnalytics"),
			"application/json",
			payload,
		)
	}

	engine := c.Engine()
	configuration := engine.GetConfiguration().Clone()
	configuration.Set(configuration2.FLAG_EXPERIMENTAL, true)
	analyticsMu.Lock()
	_, err = engine.InvokeWithInputAndConfig(
		localworkflows.WORKFLOWID_REPORT_ANALYTICS,
		[]workflow.Data{inputData},
		configuration,
	)
	analyticsMu.Unlock()

	// This workflow should fail silently if the endpoint can not be found and write the error to the log.
	if err != nil {
		logger.Err(err).Msg("error invoking workflow")
	}
	return nil
}

func PayloadForAnalyticsEventParam(c *config.Config, param types.AnalyticsEventParam) analytics.InstrumentationCollector {
	ic := analytics.NewInstrumentationCollector()
	// Add to the interaction attribute in the analytics event
	if param.InteractionUUID == "" {
		param.InteractionUUID = uuid.New().String()
	}

	iid := instrumentation.AssembleUrnFromUUID(param.InteractionUUID)

	//Set the final type attribute of the analytics event
	ic.SetType("analytics")
	ic.SetInteractionId(iid)
	ic.SetStage("dev")
	ic.AddExtension("device_id", c.DeviceID())
	for s, a := range param.Extension {
		ic.AddExtension(s, a)
	}
	ua := util.GetUserAgent(c.Engine().GetConfiguration(), config.Version)
	ic.SetUserAgent(ua)

	ic.SetTimestamp(time.UnixMilli(param.TimestampMs))
	ic.SetInteractionType(param.InteractionType)
	ic.SetStatus(analytics.Status(param.Status))
	ic.SetCategory(param.Category)
	ic.SetTargetId(param.TargetId)
	return ic
}
