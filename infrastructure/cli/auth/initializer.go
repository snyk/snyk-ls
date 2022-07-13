package auth

import (
	"context"

	"github.com/snyk/snyk-ls/application/config"
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

	i.authenticator.Authenticate(context.Background())
}
