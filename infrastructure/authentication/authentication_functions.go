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

package authentication

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"

	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"

	"github.com/snyk/snyk-ls/application/config"
)

type AuthenticationFunction func() (string, error)

type ActiveUser struct {
	Id       string `json:"id"`
	UserName string `json:"username,omitempty"`
	Orgs     []struct {
		Name  string `json:"name,omitempty"`
		Id    string `json:"id,omitempty"`
		Group struct {
			Name string `json:"name,omitempty"`
			Id   string `json:"id,omitempty"`
		} `json:"group,omitempty"`
	} `json:"orgs,omitempty"`
}

func AuthenticationCheck() (string, error) {
	user, err := GetActiveUser()
	if err != nil {
		return "", errors.Wrap(err, "failed to get active user")
	}
	return user.Id, err
}

func GetActiveUser() (*ActiveUser, error) {
	c := config.CurrentConfig()
	c.Logger().Debug().Str("method", "getActiveUser").Msg("checking active user")
	if c.Token() == "" {
		return nil, errors.New("no credentials found")
	}
	globalConf := c.Engine().GetConfiguration()
	conf := globalConf.Clone()
	c.Logger().Trace().Str("method", "getActiveUser").
		Str("configInstance", fmt.Sprintf("%p", globalConf)).
		Str("configClone", fmt.Sprintf("%p", conf)).
		Msg("invoking whoami workflow")
	conf.Set(configuration.FLAG_EXPERIMENTAL, true)
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
		return nil, errors.Wrap(err, "unable to unmarshal user data")
	}

	return &user, nil
}
