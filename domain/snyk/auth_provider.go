package snyk

import (
	"context"
	"errors"
)

type AuthenticationProvider interface {
	Authenticate(ctx context.Context) (string, error)
	ClearAuthentication(ctx context.Context) error
	AuthURL(ctx context.Context) (string, error)
}

var ErrEmptyAPIToken = errors.New("auth-provider: api token is not set")
