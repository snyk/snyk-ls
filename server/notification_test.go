package server

import (
	"context"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/lsp"

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
)

type ServerImplMock struct{}

var notified bool

func (b *ServerImplMock) Callback(ctx context.Context, method string, params interface{}) (*jrpc2.Response, error) { // todo: check if better way exists, mocking? go mock / testify
	notified = true
	return nil, nil
}
func (b *ServerImplMock) Notify(ctx context.Context, method string, params interface{}) error {
	notified = true
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
	defer func() { notified = false }()

	assert.Eventually(t, func() bool {
		return notified
	}, 2*time.Second, 10*time.Millisecond)

	disposeProgressListener()
}

func TestServerInitializeShouldStartProgressListener(t *testing.T) {
	loc, teardownServer := setupServer()
	defer teardownServer(&loc)

	clientParams := lsp.InitializeParams{
		Capabilities: sglsp.ClientCapabilities{
			Window: sglsp.WindowClientCapabilities{
				WorkDoneProgress: true,
			},
		},
	}

	rsp, err := loc.Client.Call(ctx, "initialize", clientParams)
	if err != nil {
		log.Fatal().Err(err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		log.Fatal().Err(err)
	}

	expectedProgress := progress.New("title", "message", true)
	progress.BeginProgress(expectedProgress, progress.ProgressChannel)

	// should receive progress notification

	// wait for notification
	assert.Eventually(t, func() bool { return notificationMessage != nil }, 5*time.Second, 10*time.Millisecond)
	if !t.Failed() {
		actualProgress := lsp.ProgressParams{}
		_ = notificationMessage.UnmarshalParams(&actualProgress)
		assert.Equal(t, expectedProgress.Token, actualProgress.Token)
		assert.Equal(t, expectedProgress.Value, expectedProgress.Value)
	}
}

func TestServerInitializeShouldNotStartProgressListener(t *testing.T) {
	loc, teardownServer := setupServer()
	defer teardownServer(&loc)

	clientParams := lsp.InitializeParams{
		Capabilities: sglsp.ClientCapabilities{
			Window: sglsp.WindowClientCapabilities{
				WorkDoneProgress: false,
			},
		},
	}

	rsp, err := loc.Client.Call(ctx, "initialize", clientParams)
	if err != nil {
		log.Fatal().Err(err)
	}
	var result lsp.InitializeResult
	if err := rsp.UnmarshalResult(&result); err != nil {
		log.Fatal().Err(err)
	}

	expectedProgress := progress.New("title", "message", true)
	progress.ProgressChannel <- expectedProgress

	// should not receive progress notification

	// ensure callback doesn't happen
	assert.Never(t, func() bool { return notificationMessage != nil }, 5*time.Second, 10*time.Millisecond)
}

func TestShutdownDisposesProgressListener(t *testing.T) {
	loc, teardownServer := setupServer()
	defer teardownServer(&loc)

	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		log.Fatal().Err(err)
	}

	expectedProgress := progress.New("title", "message", true)
	progress.ProgressChannel <- expectedProgress

	// should not receive progress notification after shutdown
	assert.Nil(t, notificationMessage)
}

func TestCancelProgress(t *testing.T) {
	loc, teardownServer := setupServer()
	defer teardownServer(&loc)

	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		log.Fatal().Err(err)
	}

	expectedWorkdoneProgressCancelParams := lsp.WorkdoneProgressCancelParams{
		Token: "token",
	}
	_, err = loc.Client.Call(ctx, "window/workDoneProgress/cancel", expectedWorkdoneProgressCancelParams)
	if err != nil {
		log.Fatal().Err(err)
	}

	actualToken := <-progress.CancelProgressChannel

	assert.Equal(t, expectedWorkdoneProgressCancelParams.Token, actualToken)
}

func Test_NotifierShouldSendNotificationToClient(t *testing.T) {
	loc, teardownServer := setupServer()
	defer teardownServer(&loc)

	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		log.Fatal().Err(err)
	}
	var expected = lsp.AuthenticationParams{Token: "test token"}
	var actual = lsp.AuthenticationParams{}
	notification.Send(expected.Token)
	assert.Eventually(t, func() bool {
		return notificationMessage != nil
	}, time.Minute, time.Millisecond)
	if !t.Failed() {
		err := notificationMessage.UnmarshalParams(&actual)
		assert.NoError(t, err)
		assert.True(t, notificationMessage.IsNotification())
		assert.Equal(t, expected, actual)
	}
}
