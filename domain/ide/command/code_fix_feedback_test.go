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
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/internal/types"
)

type fakeCodeHttpClient struct {
	shouldError       bool
	feedbackSubmitted string
	fixId             string
	mu                sync.Mutex
	wg                sync.WaitGroup
}

func (c *fakeCodeHttpClient) SubmitAutofixFeedback(ctx context.Context, fixId string, feedback string) error {
	defer c.wg.Done()
	c.mu.Lock()
	c.feedbackSubmitted = feedback
	c.fixId = fixId
	c.mu.Unlock()
	
	if !c.shouldError {
		return nil
	}

	return errors.New("api call failed")
}

func Test_codeFixFeedback_SubmittedSuccessfully(t *testing.T) {
	apiClient := fakeCodeHttpClient{}
	codeFixFeedbackCmd := codeFixFeedback{
		command: types.CommandData{
			Arguments: []any{"fixId", code.FixPositiveFeedback},
		},
		apiClient: &apiClient,
	}

	apiClient.wg.Add(1)
	_, err := codeFixFeedbackCmd.Execute(context.Background())
	apiClient.wg.Wait()

	assert.NoError(t, err)
	assert.Equal(t, code.FixPositiveFeedback, apiClient.feedbackSubmitted)
	assert.Equal(t, "fixId", apiClient.fixId)
}
