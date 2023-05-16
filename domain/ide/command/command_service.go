/*
 * © 2023 Snyk Limited All rights reserved.
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
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/sourcegraph/go-lsp"

	noti "github.com/snyk/snyk-ls/domain/ide/notification"
	"github.com/snyk/snyk-ls/domain/snyk"
)

var instance snyk.CommandService

type serviceImpl struct {
	authService snyk.AuthenticationService
	notifier    noti.Notifier
}

func NewService(authService snyk.AuthenticationService, notifier noti.Notifier) snyk.CommandService {
	return &serviceImpl{
		authService: authService,
		notifier:    notifier,
	}
}

// SetService sets the singleton instance of the command service.
func SetService(service snyk.CommandService) {
	instance = service
}

// Service returns the singleton instance of the command service. If not already created,
// it will create a new instance.
func Service() snyk.CommandService {
	return instance
}

// ExecuteCommand implements Service
func (service *serviceImpl) ExecuteCommand(ctx context.Context, command snyk.Command) (any, error) {
	log.Debug().Str(
		"method",
		"command.serviceImpl.ExecuteCommand",
	).Msgf("executing command %s", command.Command().CommandId)

	result, err := command.Execute(ctx)
	if err != nil && strings.Contains(err.Error(), "400 Bad Request") {
		service.notifier.SendShowMessage(lsp.MTWarning, "Logging out automatically, available credentials are invalid. Please re-authenticate.")
		service.authService.Logout(ctx)
		return nil, nil
	}

	return result, err
}
