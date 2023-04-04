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

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/domain/snyk"
)

var instance snyk.CommandService

type serviceImpl struct {
}

// ResetService resets the service instance to nil. This causes the next call to
// Service to create a new instance.
func ResetService() {
	SetService(nil)
}

// SetService sets the singleton instance of the command service.
func SetService(service snyk.CommandService) {
	instance = service
}

// Service returns the singleton instance of the command service. If not already created,
// it will create a new instance.
func Service() snyk.CommandService {
	if instance == nil {
		instance = &serviceImpl{}
	}
	return instance
}

// ExecuteCommand implements Service
func (service *serviceImpl) ExecuteCommand(ctx context.Context, command snyk.Command) error {
	log.Debug().Str(
		"method",
		"command.serviceImpl.ExecuteCommand",
	).Msgf("executing command %s", command.Command().CommandId)
	return command.Execute(ctx)
}
