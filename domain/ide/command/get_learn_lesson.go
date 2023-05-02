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

package command

import (
	"context"
	"strings"

	"github.com/pkg/errors"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/internal/lsp"
)

type getLearnLesson struct {
	command      snyk.CommandData
	srv          lsp.Server
	learnService learn.Service
}

func (cmd *getLearnLesson) Command() snyk.CommandData {
	return cmd.command
}

func (cmd *getLearnLesson) Execute(_ context.Context) (any, error) {
	args := cmd.command.Arguments
	if len(args) < 5 {
		return nil, errors.New("command is missing arguments. expected: rule, ecosystem, cwes, cves, issueType")
	}

	lesson, err := learnLesson(args, cmd.learnService)
	return lesson, err
}

func learnLesson(args []any, learnService learn.Service) (learn.Lesson, error) {
	rule := args[0].(string)
	ecosystem := args[1].(string)
	cwes := strings.Split(args[2].(string), ",")
	cves := strings.Split(args[3].(string), ",")
	// json numbers are mapped to float64 (https://pkg.go.dev/encoding/json#Unmarshal)
	issueType := snyk.Type(args[4].(float64))

	lesson, err := learnService.GetLesson(ecosystem, rule, cwes, cves, issueType)
	if err != nil {
		return learn.Lesson{}, errors.Wrap(err, "failed to get lesson")
	}
	return lesson, err
}
