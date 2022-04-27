package notification

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/lsp"
)

var params = lsp.AuthenticationParams{Token: "test event"}

func TestSendReceive(t *testing.T) {
	Send(params.Token)
	output := Receive()
	assert.Equal(t, params, output)
}

func TestCreateListener(t *testing.T) {
	Send(params.Token)
	called := false
	CreateListener(func(event lsp.AuthenticationParams) {
		called = true
	})
	assert.Eventually(t, func() bool {
		return called
	}, 1*time.Second, 1*time.Millisecond)
}
