package notification

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/internal/concurrency"
)

var params = lsp.AuthenticationParams{Token: "test event"}

func TestSendReceive(t *testing.T) {
	Send(params)
	output, _ := Receive()
	assert.Equal(t, params, output)
}

func TestCreateListener(t *testing.T) {
	called := concurrency.AtomicBool{}
	CreateListener(func(event interface{}) {
		called.Set(true)
	})
	defer DisposeListener()
	Send(params)
	assert.Eventually(t, func() bool {
		return called.Get()
	}, 2*time.Second, time.Second)
}
