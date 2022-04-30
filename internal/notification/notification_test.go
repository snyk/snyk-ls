package notification

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/lsp"
)

var params = lsp.AuthenticationParams{Token: "test event"}

func TestSendReceive(t *testing.T) {
	Send(params)
	output := Receive()
	assert.Equal(t, params, output)
}

func TestCreateListener(t *testing.T) {
	Send(params)
	called := false
	CreateListener(func(event interface{}) {
		called = true
	})
	assert.Eventually(t, func() bool {
		return called
	}, 1*time.Second, 1*time.Millisecond)
}
