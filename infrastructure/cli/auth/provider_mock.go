package auth

import (
	"context"

	"github.com/snyk/snyk-ls/domain/snyk"
)

type AuthenticationProviderMock struct {
	IsAuthenticated bool
}

func (a *AuthenticationProviderMock) Authenticate(ctx context.Context) (string, error) {
	a.IsAuthenticated = true
	return "e448dc1a-26c6-11ed-a261-0242ac120002", nil
}

func (a *AuthenticationProviderMock) ClearAuthentication(ctx context.Context) error {
	a.IsAuthenticated = false
	return nil
}

func NewMockCliAuthenticationProvider() snyk.AuthenticationProvider {
	return &AuthenticationProviderMock{}
}
