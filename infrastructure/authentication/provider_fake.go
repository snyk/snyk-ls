/*
 * © 2022-2024 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package authentication

import (
	"context"
	"errors"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/internal/types"
)

type FakeAuthenticationProvider struct {
	ExpectedAuthURL string
	IsAuthenticated bool
	// TokenToReturn, when non-empty, is returned by Authenticate() so tests can use a real token for LDX-Sync etc. while faking login.
	TokenToReturn string
	authURL       string
	Engine        workflow.Engine
}

func (a *FakeAuthenticationProvider) GetCheckAuthenticationFunction() AuthenticationFunction {
	if a.IsAuthenticated {
		a.Engine.GetLogger().Debug().Msgf("Fake Authentication - successful.")
		return func(_ workflow.Engine) (string, error) { return "fake auth successful", nil }
	}
	a.Engine.GetLogger().Debug().Msgf("Fake Authentication - failed.")
	return func(_ workflow.Engine) (string, error) {
		return "", errors.New("Authentication failed. Please update your token.")
	}
}

func (a *FakeAuthenticationProvider) Authenticate(_ context.Context) (string, error) {
	a.IsAuthenticated = true
	if a.TokenToReturn != "" {
		return a.TokenToReturn, nil
	}
	return "e448dc1a-26c6-11ed-a261-0242ac120002", nil
}

func (a *FakeAuthenticationProvider) ClearAuthentication(_ context.Context) error {
	a.IsAuthenticated = false
	return nil
}

func (a *FakeAuthenticationProvider) AuthURL(_ context.Context) string {
	return a.ExpectedAuthURL
}

func (a *FakeAuthenticationProvider) setAuthUrl(url string) {
	a.authURL = url
}

func (a *FakeAuthenticationProvider) AuthenticationMethod() types.AuthenticationMethod {
	return types.FakeAuthentication
}

func NewFakeCliAuthenticationProvider(engine workflow.Engine) *FakeAuthenticationProvider {
	return &FakeAuthenticationProvider{ExpectedAuthURL: "https://app.snyk.io/login?token=someToken", Engine: engine}
}
