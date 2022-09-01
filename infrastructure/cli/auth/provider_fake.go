package auth

import (
	"context"

	"golang.design/x/clipboard"

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

func (a *FakeAuthenticationProvider) AuthURL(ctx context.Context) error {
	a.ExpectedAuthURL = "https://app.snyk.io/login?token=someToken"
	err := clipboard.Init()
	if err != nil {
		return err
	}

	clipboard.Write(clipboard.FmtText, []byte(a.ExpectedAuthURL))

	return nil
}

func NewFakeCliAuthenticationProvider() snyk.AuthenticationProvider {
	return &FakeAuthenticationProvider{}
}
