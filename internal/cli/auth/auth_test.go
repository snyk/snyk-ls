package auth

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/internal/cli/install"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/lsp"
)

func TestAuth_authCmd(t *testing.T) {
	testutil.UnitTest(t)
	ctx := context.Background()

	authCmd, err := authCmd(ctx)

	assert.NoError(t, err)
	assertCmd(t, []string{"auth"}, authCmd)
}

func TestAuthenticate(t *testing.T) {
	testutil.IntegTest(t)
	t.Skip("This cannot work without manual authentication via web browser")
	install.Mutex.Lock()
	defer install.Mutex.Unlock()
	installer := install.NewInstaller()
	find, err := installer.Find()
	if err != nil {
		find, err = installer.Install(context.Background())
		if err != nil {
			return
		}
	}
	_ = config.CurrentConfig().SetCliPath(find)
	Authenticate()
	assert.Eventually(t, func() bool {
		payload, _ := notification.Receive()
		return payload != lsp.AuthenticationParams{}
	}, time.Second*10, time.Millisecond*100)
}
