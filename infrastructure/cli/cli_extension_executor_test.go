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

package cli

import (
	"context"
	"github.com/snyk/go-application-framework/pkg/app"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/snyk/snyk-ls/application/config"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_ExecuteLegacyCLI_SUCCESS(t *testing.T) {

	// Prepare
	cmd := []string{"snyk", "test"}
	expectedSnykCommand := cmd[1:]
	actualSnykCommand := []string{}

	expectedWorkingDir := "my work dir"
	actualWorkingDir := ""

	expectedPayload := []byte("hello")

	workflowId := workflow.NewWorkflowIdentifier("legacycli")
	engine := app.CreateAppEngine()
	_, err := engine.Register(workflowId, workflow.ConfigurationOptionsFromFlagset(&pflag.FlagSet{}), func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
		config := invocation.GetConfiguration()
		actualSnykCommand = config.GetStringSlice(configuration.RAW_CMD_ARGS)
		actualWorkingDir = config.GetString(configuration.WORKING_DIRECTORY)
		data := workflow.NewData(workflow.NewTypeIdentifier(workflowId, "testdata"), "txt", expectedPayload)
		return []workflow.Data{data}, nil
	})
	assert.Nil(t, err)

	err = engine.Init()
	assert.Nil(t, err)

	config.CurrentConfig().SetEngine(engine)

	// Run
	executorUnderTest := NewExtensionExecutor()
	actualData, err := executorUnderTest.Execute(context.Background(), cmd, expectedWorkingDir)
	assert.Nil(t, err)

	// Compare
	assert.Equal(t, actualData, expectedPayload)
	assert.Equal(t, actualSnykCommand, expectedSnykCommand)
	assert.Equal(t, actualWorkingDir, expectedWorkingDir)

}

func Test_ExecuteLegacyCLI_FAILED(t *testing.T) {

	// Prepare
	cmd := []string{"snyk", "test"}
	expectedPayload := []byte{}

	// Run
	executorUnderTest := NewExtensionExecutor()
	actualData, err := executorUnderTest.Execute(context.Background(), cmd, "")

	// Compare
	assert.NotNil(t, err)
	assert.Equal(t, actualData, expectedPayload)

}
