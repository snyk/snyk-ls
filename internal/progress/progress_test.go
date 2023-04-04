/*
 * © 2022 Snyk Limited All rights reserved.
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

package progress

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/lsp"
)

func TestBeginProgress(t *testing.T) {
	channel := make(chan lsp.ProgressParams, 2)
	progress := NewTestTracker(channel, nil)

	progress.Begin("title", "message")

	assert.Equal(
		t,
		lsp.ProgressParams{
			Token: progress.token,
			Value: nil,
		},
		<-channel,
	)

	assert.Equal(
		t,
		lsp.ProgressParams{
			Token: progress.token,
			Value: lsp.WorkDoneProgressBegin{
				WorkDoneProgressKind: lsp.WorkDoneProgressKind{Kind: "begin"},
				Title:                "title",
				Cancellable:          true,
				Message:              "message",
				Percentage:           1,
			},
		},
		<-channel,
	)
}

func TestReportProgress(t *testing.T) {
	output := lsp.ProgressParams{
		Token: "token",
		Value: lsp.WorkDoneProgressReport{
			WorkDoneProgressKind: lsp.WorkDoneProgressKind{Kind: "report"},
			Percentage:           10,
		},
	}
	channel := make(chan lsp.ProgressParams, 2)
	progress := NewTestTracker(channel, nil)

	workProgressReport := output.Value.(lsp.WorkDoneProgressReport)
	progress.Report(workProgressReport.Percentage)

	assert.Equal(t, output, <-channel)
}

func TestEndProgress(t *testing.T) {
	output := lsp.ProgressParams{
		Token: "token",
		Value: lsp.WorkDoneProgressEnd{
			WorkDoneProgressKind: lsp.WorkDoneProgressKind{Kind: "end"},
			Message:              "end message",
		},
	}

	channel := make(chan lsp.ProgressParams, 2)
	progress := NewTestTracker(channel, nil)

	workProgressEnd := output.Value.(lsp.WorkDoneProgressEnd)
	progress.End(workProgressEnd.Message)

	assert.Equal(t, output, <-channel)
}

func TestEndProgressTwice(t *testing.T) {
	output := lsp.ProgressParams{
		Token: "token",
		Value: lsp.WorkDoneProgressEnd{
			WorkDoneProgressKind: lsp.WorkDoneProgressKind{Kind: "end"},
			Message:              "end message",
		},
	}

	channel := make(chan lsp.ProgressParams, 2)
	progress := NewTestTracker(channel, nil)

	workProgressEnd := output.Value.(lsp.WorkDoneProgressEnd)
	progress.End(workProgressEnd.Message)

	assert.Panics(t, func() {
		progress.End(workProgressEnd.Message)
	})
}
