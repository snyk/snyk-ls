package auth

import (
	"context"

	"github.com/snyk/snyk-ls/domain/snyk"
)

type FakeAuthenticationProvider struct {
	ExpectedAuthURL string
	IsAuthenticated bool
}

func (a *FakeAuthenticationProvider) Authenticate(ctx context.Context) (string, error) {
	a.IsAuthenticated = true
	return "e448dc1a-26c6-11ed-a261-0242ac120002", nil
}

func (a *FakeAuthenticationProvider) ClearAuthentication(ctx context.Context) error {
	a.IsAuthenticated = false
	return nil
}

func (a *FakeAuthenticationProvider) AuthURL(ctx context.Context) string {
	return a.ExpectedAuthURL
}

func NewFakeCliAuthenticationProvider() snyk.AuthenticationProvider {
	return &FakeAuthenticationProvider{"https://app.snyk.io/login?token=someToken", false}
}
