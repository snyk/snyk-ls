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

func Test_NotifierShouldSendNotificationToClient(t *testing.T) {
	loc, teardownServer := setupServer()
	defer teardownServer(&loc)

	_, err := loc.Client.Call(ctx, "initialize", nil)
	if err != nil {
		log.Fatal().Err(err)
	}
	preconditions.EnsureReadyForAnalysisAndWait()
	var expected = lsp.AuthenticationParams{Token: "test token"}
	var actual = lsp.AuthenticationParams{}
	notification.Send(expected)
	assert.Eventually(t, func() bool {
		if notificationRequest == nil {
			return false
		}
		err := notificationRequest.UnmarshalParams(&actual)
		return err == nil && actual.Token == expected.Token
	}, time.Minute, time.Millisecond)
	assert.True(t, notificationRequest.IsNotification())

	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}
