package auth

import (
	"context"

	"golang.design/x/clipboard"

	"github.com/snyk/snyk-ls/domain/snyk"
)

type FakeAuthenticationProvider struct {
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

func (a *FakeAuthenticationProvider) AuthURL(ctx context.Context) error {
	err := clipboard.Init()
	if err != nil {
		return err
	}

	clipboard.Write(clipboard.FmtText, []byte("https://app.snyk.io/login?token=someToken"))

	return nil
}

func NewFakeCliAuthenticationProvider() snyk.AuthenticationProvider {
	return &FakeAuthenticationProvider{}
}
