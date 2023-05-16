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

package command

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/lsp"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_getActiveUser_Execute_User_found(t *testing.T) {
	testutil.UnitTest(t)
	cmd := &getActiveUser{
		command: snyk.CommandData{
			CommandId: snyk.GetActiveUserCommand,
		},
	}

	expectedUser, expectedUserData := whoamiWorkflowResponse(t)

	c := config.CurrentConfig()
	c.SetAuthenticationMethod(lsp.OAuthAuthentication)
	mockEngine, engineConfig := setUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	mockEngine.EXPECT().InvokeWithConfig(localworkflows.WORKFLOWID_WHOAMI, gomock.Any()).Return(expectedUserData, nil)

	actualUser, err := cmd.Execute(context.Background())

	assert.NoErrorf(t, err, "cmd.Execute() error = %v", err)
	assert.Equal(t, expectedUser, actualUser)
}

func Test_getActiveUser_Execute_Result_Empty(t *testing.T) {
	testutil.UnitTest(t)
	cmd := &getActiveUser{
		command: snyk.CommandData{
			CommandId: snyk.GetActiveUserCommand,
		},
	}

	c := config.CurrentConfig()
	c.SetAuthenticationMethod(lsp.OAuthAuthentication)
	mockEngine, engineConfig := setUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	mockEngine.EXPECT().InvokeWithConfig(localworkflows.WORKFLOWID_WHOAMI, gomock.Any()).Return([]workflow.Data{}, nil)

	actualUser, err := cmd.Execute(context.Background())

	assert.Errorf(t, err, "cmd.Execute() error = %v", err)
	assert.Empty(t, actualUser)
}

func Test_getActiveUser_Execute_Error_Result(t *testing.T) {
	testutil.UnitTest(t)
	cmd := &getActiveUser{
		command: snyk.CommandData{
			CommandId: snyk.GetActiveUserCommand,
		},
	}

	c := config.CurrentConfig()
	c.SetAuthenticationMethod(lsp.OAuthAuthentication)
	mockEngine, engineConfig := setUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	testError := errors.New("test error")
	mockEngine.EXPECT().InvokeWithConfig(localworkflows.WORKFLOWID_WHOAMI, gomock.Any()).Return([]workflow.Data{}, testError)

	actualUser, err := cmd.Execute(context.Background())

	assert.Errorf(t, err, "cmd.Execute() error = %v", err)
	assert.Empty(t, actualUser)
}

func whoamiWorkflowResponse(t *testing.T) (*snyk.ActiveUser, []workflow.Data) {
	expectedUser := snyk.ActiveUser{
		Id:       "id",
		UserName: "username",
	}
	expectedUserJSON, err := json.Marshal(expectedUser)
	assert.NoError(t, err)

	expectedUserData := []workflow.Data{
		workflow.NewData(
			workflow.NewTypeIdentifier(localworkflows.WORKFLOWID_WHOAMI, "payload"),
			"application/json",
			expectedUserJSON),
	}
	return &expectedUser, expectedUserData
}
