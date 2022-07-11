package auth

import (
	"context"

	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/notification"
)

type Initializer struct {
	authenticator *Authenticator
}

func NewInitializer(authenticator *Authenticator) *Initializer {
	return &Initializer{
		authenticator: authenticator,
	}
}

func (i *Initializer) Init() {
	authenticated := config.CurrentConfig().Authenticated()

	if authenticated {
		return
	}

	notification.Send(sglsp.ShowMessageParams{Type: sglsp.Info, Message: "Authenticating to Snyk. This could open a browser window."})
	i.authenticator.Authenticate(context.Background())
}
