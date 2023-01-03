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

package server

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/internal/concurrency"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/progress"
)

type ServerImplMock struct{}

var notified = concurrency.AtomicBool{}

func (b *ServerImplMock) Callback(_ context.Context, _ string, _ any) (*jrpc2.Response, error) { // todo: check if better way exists, mocking? go mock / testify
	notified.Set(true)
	return nil, nil
}
func (b *ServerImplMock) Notify(_ context.Context, _ string, _ any) error {
	notified.Set(true)
	return nil
}

func TestCreateProgressListener(t *testing.T) {
	progressChannel := make(chan lsp.ProgressParams, 1)
	progressNotification := lsp.ProgressParams{
		Token: "token",
		Value: lsp.WorkDoneProgressBegin{
			WorkDoneProgressKind: lsp.WorkDoneProgressKind{Kind: "begin"},
			Title:                "title",
			Message:              "message",
			Cancellable:          true,
			Percentage:           0,
		},
	}
	progressChannel <- progressNotification

	server := ServerImplMock{}

	go createProgressListener(progressChannel, &server)
	defer func() { notified.Set(false) }()

	assert.Eventually(t, func() bool {
		return notified.Get()
	}, 2*time.Second, 10*time.Millisecond)

	disposeProgressListener()
}

func TestServerInitializeShouldStartProgressListener(t *testing.T) {
	loc := setupServer(t)

	clientParams := lsp.InitializeParams{
		Capabilities: sglsp.ClientCapabilities{
			Window: sglsp.WindowClientCapabilities{
				WorkDoneProgress: true,
			},
		},
	}

	rsp, err := loc.Client.Call(ctx, "initialize", clientParams)
	if err != nil {
		t.Fatal(err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		t.Fatal(err)
	}

	progressTracker := progress.NewTracker(true)
	progressTracker.Begin("title", "message")
	// should receive progress notification
	assert.Eventually(
		t,
		func() bool {
			callbacks := jsonRPCRecorder.FindCallbacksByMethod("window/workDoneProgress/create")
			for _, c := range callbacks {
				actualProgress := lsp.ProgressParams{}
				_ = c.UnmarshalParams(&actualProgress)
				if progressTracker.GetToken() == actualProgress.Token {
					return true
				}
			}
			return false
		},
		5*time.Second,
		10*time.Millisecond,
	)
}

func TestCancelProgress(t *testing.T) {
	loc := setupServer(t)

	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}

	expectedWorkdoneProgressCancelParams := lsp.WorkdoneProgressCancelParams{
		Token: "token",
	}
	_, err = loc.Client.Call(ctx, "window/workDoneProgress/cancel", expectedWorkdoneProgressCancelParams)
	if err != nil {
		t.Fatal(err)
	}

	assert.Eventually(t, func() bool {
		actualToken := <-progress.CancelProgressChannel
		return expectedWorkdoneProgressCancelParams.Token == actualToken
	}, time.Second*5, time.Millisecond)

}

func Test_NotifierShouldSendNotificationToClient(t *testing.T) {
	loc := setupServer(t)

	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	var expected = lsp.AuthenticationParams{Token: "test token"}

	notification.Send(expected)
	assert.Eventually(
		t,
		func() bool {
			notifications := jsonRPCRecorder.FindNotificationsByMethod("$/snyk.hasAuthenticated")
			if len(notifications) < 1 {
				return false
			}
			for _, n := range notifications {
				var actual = lsp.AuthenticationParams{}
				_ = n.UnmarshalParams(&actual)
				if reflect.DeepEqual(expected, actual) {
					return true
				}
			}
			return false
		},
		2*time.Second,
		10*time.Millisecond,
	)
}

func Test_IsAvailableCliNotification(t *testing.T) {
	loc := setupServer(t)

	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		t.Fatal(err)
	}
	var expected = lsp.SnykIsAvailableCli{CliPath: "path"}

	notification.Send(expected)
	assert.Eventually(
		t,
		func() bool {
			notifications := jsonRPCRecorder.FindNotificationsByMethod("$/snyk.isAvailableCli")
			if len(notifications) < 1 {
				return false
			}
			for _, n := range notifications {
				var actual = lsp.SnykIsAvailableCli{}
				_ = n.UnmarshalParams(&actual)
				if reflect.DeepEqual(expected, actual) {
					return true
				}
			}
			return false
		},
		2*time.Second,
		10*time.Millisecond,
	)
}
