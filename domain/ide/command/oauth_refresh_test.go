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
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	auth2 "github.com/snyk/go-application-framework/pkg/auth"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/services"
	"github.com/snyk/snyk-ls/internal/lsp"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_oauthRefreshCommand_Execute_SameTokenNoUpdate(t *testing.T) {
	testutil.UnitTest(t)
	cmd := &oauthRefreshCommand{
		command: snyk.CommandData{
			CommandId: snyk.OAuthRefreshCommand,
		},
		authService: services.NewAuthenticationService(
			&snyk.FakeAuthenticationProvider{IsAuthenticated: true},
			ux.NewTestAnalytics(),
			error_reporting.NewTestErrorReporter(),
			notification.NewNotifier(),
		),
	}

	c := config.CurrentConfig()
	c.SetAuthenticationMethod(lsp.OAuthAuthentication)
	mockEngine, engineConfig := setUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	mockEngine.EXPECT().InvokeWithConfig(localworkflows.WORKFLOWID_WHOAMI, gomock.Any())

	_, err := cmd.Execute(context.Background())

	assert.NoErrorf(t, err, "cmd.Execute() error = %v", err)
}

func Test_oauthRefreshCommand_Execute_DifferentTokenUpdate(t *testing.T) {
	testutil.UnitTest(t)
	analytics := ux.NewTestAnalytics()
	notifier := notification.NewNotifier()
	cmd := &oauthRefreshCommand{
		command: snyk.CommandData{
			CommandId: snyk.OAuthRefreshCommand,
		},
		authService: services.NewAuthenticationService(
			&snyk.FakeAuthenticationProvider{IsAuthenticated: true},
			analytics,
			error_reporting.NewTestErrorReporter(),
			notifier,
		),
	}

	c := config.CurrentConfig()
	c.SetAuthenticationMethod(lsp.OAuthAuthentication)
	mockEngine, engineConfig := setUpEngineMock(t, c)
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	mockEngine.EXPECT().InvokeWithConfig(localworkflows.WORKFLOWID_WHOAMI, gomock.Any())

	engineConfig.Set(auth2.CONFIG_KEY_OAUTH_TOKEN, "something different")
	assert.NotEqual(t, c.Token(), engineConfig.GetString(auth2.CONFIG_KEY_OAUTH_TOKEN), "token should be different")

	notifier.DisposeListener()
	receivedChan := make(chan bool)
	notifier.CreateListener(func(params any) {
		if reflect.TypeOf(params) == reflect.TypeOf(lsp.AuthenticationParams{}) {
			receivedChan <- true
		}
	})

	_, err := cmd.Execute(context.Background())

	assert.NoErrorf(t, err, "cmd.Execute() error = %v", err)
	assert.Equal(t, c.Token(), engineConfig.GetString(auth2.CONFIG_KEY_OAUTH_TOKEN))
	assert.True(t, analytics.Identified)
	assert.Eventuallyf(t, func() bool {
		return <-receivedChan
	}, time.Second, time.Millisecond, "should receive notification")
}
