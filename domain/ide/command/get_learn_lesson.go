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
	"github.com/snyk/snyk-ls/internal/types"
)

type getLearnLesson struct {
	command      types.CommandData
	srv          types.Server
	learnService learn.Service
}

func (cmd *getLearnLesson) Command() types.CommandData {
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

func learnLesson(args []any, learnService learn.Service) (*learn.Lesson, error) {
	rule, ok := args[0].(string)
	if !ok {
		return nil, errors.New("learn lesson rule is not a string")
	}
	ecosystem, ok := args[1].(string)
	if !ok {
		return nil, errors.New("learn lesson ecosystem is not a string")
	}
	cwesArg, ok := args[2].(string)
	if !ok {
		return nil, errors.New("learn lesson cwes is not a string")
	}
	cwes := strings.Split(cwesArg, ",")
	cvesArg, ok := args[3].(string)
	if !ok {
		return nil, errors.New("learn lesson cves is not a string")
	}
	cves := strings.Split(cvesArg, ",")
	// json numbers are mapped to float64 (https://pkg.go.dev/encoding/json#Unmarshal)
	issueTypeArg, ok := args[4].(float64)
	if !ok {
		return nil, errors.New("learn lesson issueType is not a number")
	}
	issueType := snyk.Type(issueTypeArg)

	lesson, err := learnService.GetLesson(ecosystem, rule, cwes, cves, issueType)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get lesson")
	}
	return lesson, err
}
