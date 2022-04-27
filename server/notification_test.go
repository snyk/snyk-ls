package server

import (
	"testing"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/preconditions"
	"github.com/snyk/snyk-ls/lsp"
)

func Test_AuthenticationShouldSendNotificationToClient(t *testing.T) {
	loc, teardownServer := setupServer()
	defer teardownServer(&loc)

	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		log.Fatal().Err(err)
	}
	preconditions.EnsureReadyForAnalysisAndWait()
	var params = lsp.AuthenticationParams{}
	testToken := "test token"
	notification.Send(testToken)
	assert.Eventually(t, func() bool {
		if notificationRequest == nil {
			return false
		}
		err := notificationRequest.UnmarshalParams(&params)
		return err == nil
	}, time.Minute*1, time.Millisecond*2)
	assert.True(t, notificationRequest.IsNotification())

	assert.NoError(t, err)
	assert.Equal(t, testToken, params.Token)
}
