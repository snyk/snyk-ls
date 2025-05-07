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
	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_codeFixFeedback_SubmittedSuccessfully(t *testing.T) {
	codeFixFeedbackCmd := codeFixFeedback{
		command: types.CommandData{
			Arguments: []any{"fixId", code.FixPositiveFeedback},
		},
	}

	_, err := codeFixFeedbackCmd.Execute(context.Background())

	assert.NoError(t, err)
}
