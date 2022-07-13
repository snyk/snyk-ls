package auth

import (
	"context"

	"github.com/google/uuid"
)

type TestAuthenticationProvider struct {
	token string
}

func (t *TestAuthenticationProvider) Authenticate(ctx context.Context) error {
	t.token = uuid.New().String()
	return nil
}

func (*TestAuthenticationProvider) ClearToken(ctx context.Context) error {
	panic("unimplemented")
}

func (t *TestAuthenticationProvider) GetToken(ctx context.Context) (string, error) {
	if t.token == "" {
		return "", ErrEmptyAPIToken
	}

	return t.token, nil
}
