/*
 * © 2023-2024 Snyk Limited
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

package command

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_ExecuteCommand(t *testing.T) {
	c := testutil.UnitTest(t)
	authProvider := &authentication.FakeAuthenticationProvider{
		ExpectedAuthURL: "https://auth.url",
	}
	authenticationService := authentication.NewAuthenticationService(c, []authentication.AuthenticationProvider{authProvider}, nil, nil)
	service := NewService(authenticationService, nil, nil, nil, nil, nil)
	cmd := types.CommandData{
		CommandId: types.CopyAuthLinkCommand,
	}

	url, _ := service.ExecuteCommandData(context.Background(), cmd, nil)

	assert.Equal(t, "https://auth.url", url)
}
