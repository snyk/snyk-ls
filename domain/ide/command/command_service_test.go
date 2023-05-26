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

	"github.com/snyk/snyk-ls/domain/snyk"
)

type TestCommand struct {
	executed bool
}

func (command *TestCommand) Command() snyk.CommandData {
	return snyk.CommandData{}
}
func (command *TestCommand) Execute(_ context.Context) (any, error) {
	command.executed = true
	return nil, nil
}

// func Test_ExecuteCommand(t *testing.T) {
// 	service := NewService(nil, nil, nil, nil, nil)
// 	cmd := &TestCommand{}
// 	_, _ = service.ExecuteCommandData(context.Background(), cmd)
// 	assert.True(t, cmd.executed)
// }
