/*
 * © 2023 Snyk Limited
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

package snyk

import (
	"encoding/json"

	"github.com/pkg/errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/lsp"
)

func AuthenticationCheck() (string, error) {
	user, err := GetActiveUser()
	if err != nil {
		return "", errors.Wrap(err, "failed to get active user")
	}
	return user.Id, err
}

func GetActiveUser() (*ActiveUser, error) {
	c := config.CurrentConfig()
	conf := c.Engine().GetConfiguration().Clone()
	if c.AuthenticationMethod() == lsp.OAuthAuthentication {
		conf.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, 1)
	} else {
		conf.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, 0)
	}
	conf.Set("experimental", true)
	conf.Set("json", true)
	result, err := c.Engine().InvokeWithConfig(localworkflows.WORKFLOWID_WHOAMI, conf)

	if err != nil {
		return nil, errors.Wrap(err, "failed to invoke whoami workflow")
	}
	if len(result) == 0 {
		return nil, errors.New("no user data found")
	}

	payload := result[0].GetPayload()

	if payload == nil {
		return nil, errors.New("no payload found")
	}

	payloadBytes, ok := payload.([]byte)
	if !ok {
		return nil, errors.New("payload is not a byte array")
	}

	var user ActiveUser
	err = json.Unmarshal(payloadBytes, &user)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal user data")
	}

	return &user, nil
}
