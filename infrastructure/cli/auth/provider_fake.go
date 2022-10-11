/*
 * Copyright 2022 Snyk Ltd.
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

func (a *FakeAuthenticationProvider) AuthenticateToken(_ string) error {
	return nil
}

func NewFakeCliAuthenticationProvider() snyk.AuthenticationProvider {
	return &FakeAuthenticationProvider{"https://app.snyk.io/login?token=someToken", false}
}
