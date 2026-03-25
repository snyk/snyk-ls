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
	"sync"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
)

type FakeAuthenticationProvider struct {
	ExpectedAuthURL           string
	IsAuthenticated           bool
	ClearAuthenticationCalled bool
	Method                    types.AuthenticationMethod
	authURL                   string
	C                         *config.Config
}

func (a *FakeAuthenticationProvider) GetCheckAuthenticationFunction() AuthenticationFunction {
	if a.IsAuthenticated {
		a.C.Logger().Debug().Msgf("Fake Authentication - successful.")
		return func() (string, error) { return "fake auth successful", nil }
	}
	a.C.Logger().Debug().Msgf("Fake Authentication - failed.")
	return func() (string, error) { return "", errors.New("Authentication failed. Please update your token.") }
}

func (a *FakeAuthenticationProvider) Authenticate(_ context.Context) (string, error) {
	a.IsAuthenticated = true
	return "e448dc1a-26c6-11ed-a261-0242ac120002", nil
}

func (a *FakeAuthenticationProvider) ClearAuthentication(_ context.Context) error {
	a.IsAuthenticated = false
	a.ClearAuthenticationCalled = true
	return nil
}

func (a *FakeAuthenticationProvider) AuthURL(_ context.Context) string {
	return a.ExpectedAuthURL
}

func (a *FakeAuthenticationProvider) setAuthUrl(url string) {
	a.authURL = url
}

func (a *FakeAuthenticationProvider) AuthenticationMethod() types.AuthenticationMethod {
	if a.Method != "" {
		return a.Method
	}
	return types.FakeAuthentication
}

func NewFakeCliAuthenticationProvider(c *config.Config) *FakeAuthenticationProvider {
	return &FakeAuthenticationProvider{ExpectedAuthURL: "https://app.snyk.io/login?token=someToken", C: c}
}

// BlockingFakeAuthProvider is a test double whose first Authenticate call blocks until its
// context is canceled. Subsequent calls return a token immediately.
// Use Started to detect when the first Authenticate has been entered.
type BlockingFakeAuthProvider struct {
	Started    chan struct{}
	mu         sync.Mutex
	hasBlocked bool
}

func NewBlockingFakeAuthProvider() *BlockingFakeAuthProvider {
	return &BlockingFakeAuthProvider{Started: make(chan struct{})}
}

func (b *BlockingFakeAuthProvider) Authenticate(ctx context.Context) (string, error) {
	b.mu.Lock()
	firstCall := !b.hasBlocked
	if firstCall {
		b.hasBlocked = true
	}
	b.mu.Unlock()

	if firstCall {
		close(b.Started)
		<-ctx.Done()
		return "", ctx.Err()
	}
	return "e448dc1a-26c6-11ed-a261-0242ac120002", nil
}

func (b *BlockingFakeAuthProvider) ClearAuthentication(_ context.Context) error { return nil }
func (b *BlockingFakeAuthProvider) AuthURL(_ context.Context) string            { return "" }
func (b *BlockingFakeAuthProvider) setAuthUrl(_ string)                         {}
func (b *BlockingFakeAuthProvider) GetCheckAuthenticationFunction() AuthenticationFunction {
	return func() (string, error) { return "", nil }
}
func (b *BlockingFakeAuthProvider) AuthenticationMethod() types.AuthenticationMethod {
	return types.FakeAuthentication
}
