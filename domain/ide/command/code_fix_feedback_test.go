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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/types"
)

type fakeCodeHttpClient struct {
	shouldError       bool
	feedbackSubmitted bool
}

func (c *fakeCodeHttpClient) SubmitAutofixFeedback(ctx context.Context, fixId string, positive bool) error {
	if !c.shouldError {
		c.feedbackSubmitted = true
		return nil
	}

	return errors.New("api call failed")
}

func Test_codeFixFeedback_SubmittedSuccessfully(t *testing.T) {
	apiClient := fakeCodeHttpClient{}
	codeFixFeedbackCmd := codeFixFeedback{
		command: types.CommandData{
			Arguments: []any{"fixId", true},
		},
		apiClient: &apiClient,
	}

	_, err := codeFixFeedbackCmd.Execute(context.Background())
	assert.NoError(t, err)
	assert.True(t, apiClient.feedbackSubmitted)
}

func Test_codeFixFeedback_SubmissionFailed(t *testing.T) {
	apiClient := fakeCodeHttpClient{
		shouldError: true,
	}
	codeFixFeedbackCmd := codeFixFeedback{
		command: types.CommandData{
			Arguments: []any{"fixId", true},
		},
		apiClient: &apiClient,
	}

	_, err := codeFixFeedbackCmd.Execute(context.Background())
	assert.Error(t, err)
	assert.False(t, apiClient.feedbackSubmitted)
}
