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

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/types"
)

func TestBeginProgress(t *testing.T) {
	channel := make(chan types.ProgressParams, 100000)
	cancelChannel := make(chan bool, 1)
	logger := zerolog.Nop()
	progress := NewTestTracker(channel, cancelChannel, &logger)

	progress.BeginWithMessage("title", "message")

	assert.Equal(
		t,
		types.ProgressParams{
			Token: progress.token,
			Value: types.WorkDoneProgressBegin{
				WorkDoneProgressKind: types.WorkDoneProgressKind{Kind: "begin"},
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
	output := types.ProgressParams{
		Token: "token",
		Value: types.WorkDoneProgressReport{
			WorkDoneProgressKind: types.WorkDoneProgressKind{Kind: "report"},
			Percentage:           10,
		},
	}
	channel := make(chan types.ProgressParams, 2)
	logger := zerolog.Nop()
	progress := NewTestTracker(channel, nil, &logger)

	workProgressReport := output.Value.(types.WorkDoneProgressReport)
	progress.Report(workProgressReport.Percentage)

	assert.Equal(t, output, <-channel)
}

func TestEndProgress(t *testing.T) {
	output := types.ProgressParams{
		Token: "token",
		Value: types.WorkDoneProgressEnd{
			WorkDoneProgressKind: types.WorkDoneProgressKind{Kind: "end"},
			Message:              "end message",
		},
	}

	channel := make(chan types.ProgressParams, 2)
	logger := zerolog.Nop()
	progress := NewTestTracker(channel, nil, &logger)

	workProgressEnd := output.Value.(types.WorkDoneProgressEnd)
	progress.EndWithMessage(workProgressEnd.Message)

	assert.Equal(t, output, <-channel)
}

// TestNewTrackerWithChannel_RoutesToGivenChannel (IDE-2036-UNIT-001) verifies
// that NewTrackerWithChannel sends progress to the supplied channel and that
// NewTracker still sends to the global ToServerProgressChannel.
//
// Not parallel: it inspects the global ToServerProgressChannel for absence; a
// concurrent NewTracker call from another test goroutine would produce false
// positives. We drain first and then write only via NewTrackerWithChannel so
// any residual item on the global channel is a genuine routing bug.
func TestNewTrackerWithChannel_RoutesToGivenChannel(t *testing.T) {
	// Drain global channel so previous test writes don't interfere.
	for len(ToServerProgressChannel) > 0 {
		<-ToServerProgressChannel
	}

	logger := zerolog.Nop()
	customCh := make(chan types.ProgressParams, 10)

	tr := NewTrackerWithChannel(customCh, false, &logger)
	tr.Begin("test-title")
	tr.End()

	// custom channel must receive the begin event
	if len(customCh) == 0 {
		t.Fatal("expected progress event on customCh, got none")
	}

	// global channel must NOT receive anything (we did not use NewTracker)
	if len(ToServerProgressChannel) != 0 {
		t.Fatal("NewTrackerWithChannel must not write to ToServerProgressChannel")
	}
}

// TestNewTracker_RoutesToGlobalChannel verifies backward compatibility: the
// existing NewTracker still routes to ToServerProgressChannel.
func TestNewTracker_RoutesToGlobalChannel(t *testing.T) {
	// Drain the global channel first so previous test runs don't interfere.
	for len(ToServerProgressChannel) > 0 {
		<-ToServerProgressChannel
	}

	logger := zerolog.Nop()
	tr := NewTracker(false, &logger)
	tr.Begin("test-title")
	tr.End()

	if len(ToServerProgressChannel) == 0 {
		t.Fatal("expected progress event on ToServerProgressChannel, got none")
	}
}

func TestEndProgressTwice(t *testing.T) {
	output := types.ProgressParams{
		Value: types.WorkDoneProgressEnd{
			WorkDoneProgressKind: types.WorkDoneProgressKind{Kind: "end"},
			Message:              "end message",
		},
	}

	channel := make(chan types.ProgressParams, 2)
	logger := zerolog.Nop()
	progress := NewTestTracker(channel, nil, &logger)

	workProgressEnd := output.Value.(types.WorkDoneProgressEnd)
	progress.EndWithMessage(workProgressEnd.Message)

	assert.Panics(t, func() {
		progress.EndWithMessage(workProgressEnd.Message)
	})
}
