/*
 * © 2025 Snyk Limited
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

package lsui

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/ui"

	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

const testTitle = "Test Title"

func setupTestLSProgressBar(t *testing.T) (*lsProgressBar, chan types.ProgressParams) {
	t.Helper()

	channel := make(chan types.ProgressParams, 100000)
	cancelChannel := make(chan bool, 1)
	testTracker := progress.NewTestTracker(channel, cancelChannel)
	bar := newTestLSProgressBar(testTracker, testTitle)

	testsupport.AssertChannelIsEmpty(t, channel)

	return bar, channel
}

// updateProgress Progress must go up by more than 10% to prevent hitting the tracker's anti-spam
func updateProgress(t *testing.T, bar *lsProgressBar, percentage float64) error {
	t.Helper()

	// Action
	return bar.UpdateProgress(percentage)
}

// updateProgressAndAssertExpected Progress must go up by more than 10% to prevent hitting the tracker's anti-spam
func updateProgressAndAssertExpected(t *testing.T, bar *lsProgressBar, channel chan types.ProgressParams, currentMsg string, haveUpdatedProgressBefore bool, percentage float64) {
	t.Helper()

	// Action
	err := updateProgress(t, bar, percentage)

	// Assertions
	assert.NoError(t, err)

	if !haveUpdatedProgressBefore {
		progressParams := testsupport.ReadMessageAssertNoWait(t, channel)
		beginReport, ok := progressParams.Value.(types.WorkDoneProgressBegin)
		assert.True(t, ok)
		assert.Equal(t, testTitle, beginReport.Title, "Title mismatch")
		assert.Equal(t, currentMsg, beginReport.Message, "Initial message mismatch")
		if percentage == ui.InfiniteProgress {
			assert.Nil(t, beginReport.Percentage, "Percentage sent when it should be omitted")
		} else {
			assert.Equal(t, 0, *beginReport.Percentage, "Percentage mismatch")
		}
	}

	progressParams := testsupport.ReadMessageAssertNoWait(t, channel)
	progressReport, ok := progressParams.Value.(types.WorkDoneProgressReport)
	assert.True(t, ok)
	assert.Equal(t, currentMsg, progressReport.Message, "Message mismatch")
	if percentage == ui.InfiniteProgress {
		assert.Nil(t, progressReport.Percentage, "Percentage sent when it should be omitted")
	} else {
		assert.Equal(t, int(math.Floor(math.Min(percentage, 1)*100)), *progressReport.Percentage, "Percentage mismatch")
	}

	testsupport.AssertChannelIsEmpty(t, channel)
}

func setMessage(t *testing.T, bar *lsProgressBar, msg string) {
	t.Helper()

	// Action
	bar.SetMessage(msg)
}

func setMessageAndAssertExpected(t *testing.T, bar *lsProgressBar, channel chan types.ProgressParams, lastReportedProgress *float64, msg string) {
	t.Helper()

	// Action
	setMessage(t, bar, msg)

	// Assertions
	if lastReportedProgress != nil {
		progressParams := testsupport.ReadMessageAssertNoWait(t, channel)
		progressReport, ok := progressParams.Value.(types.WorkDoneProgressReport)
		assert.True(t, ok)
		assert.Equal(t, msg, progressReport.Message, "Message mismatch")
		if *lastReportedProgress == ui.InfiniteProgress {
			assert.Nil(t, progressReport.Percentage, "Percentage sent when it should be omitted")
		} else {
			assert.Equal(t, int(math.Floor(math.Min(*lastReportedProgress, 1)*100)), *progressReport.Percentage, "Percentage mismatch")
		}
	}

	testsupport.AssertChannelIsEmpty(t, channel)
}

func clearAndAssertProgressEnd(t *testing.T, bar *lsProgressBar, channel chan types.ProgressParams) {
	t.Helper()

	// Action
	err := bar.Clear()

	// Assertions
	assert.NoError(t, err)

	progressParams := testsupport.ReadMessageAssertNoWait(t, channel)
	_, ok := progressParams.Value.(types.WorkDoneProgressEnd)
	assert.True(t, ok)

	testsupport.AssertChannelIsEmpty(t, channel)
}

func Test_ProgressBar_GoldenPath(t *testing.T) {
	// Setup
	bar, channel := setupTestLSProgressBar(t)

	// Test
	msg := "Initial message"
	setMessageAndAssertExpected(t, bar, channel, nil, msg)
	updateProgressAndAssertExpected(t, bar, channel, msg, false, 0)
	updateProgressAndAssertExpected(t, bar, channel, msg, true, 0.3)
	msg = "Finishing up..."
	setMessageAndAssertExpected(t, bar, channel, util.Ptr(0.3), msg)
	updateProgressAndAssertExpected(t, bar, channel, msg, true, 0.6)

	clearAndAssertProgressEnd(t, bar, channel)
}

func Test_ProgressBar_GoldenPath_Infinite(t *testing.T) {
	// Setup
	bar, channel := setupTestLSProgressBar(t)

	// Test
	msg := "Beginning..."
	setMessageAndAssertExpected(t, bar, channel, nil, msg)
	updateProgressAndAssertExpected(t, bar, channel, msg, false, ui.InfiniteProgress)
	msg = "Running..."
	setMessageAndAssertExpected(t, bar, channel, util.Ptr(ui.InfiniteProgress), msg)
	msg = "Finishing up..."
	setMessageAndAssertExpected(t, bar, channel, util.Ptr(ui.InfiniteProgress), msg)

	clearAndAssertProgressEnd(t, bar, channel)
}

func Test_ProgressBar_Handles_NoMessage(t *testing.T) {
	// Setup
	bar, channel := setupTestLSProgressBar(t)

	// Test
	updateProgressAndAssertExpected(t, bar, channel, "", false, 0)
	updateProgressAndAssertExpected(t, bar, channel, "", true, 0.3)
	updateProgressAndAssertExpected(t, bar, channel, "", true, 0.6)

	clearAndAssertProgressEnd(t, bar, channel)
}

func Test_ProgressBar_Handles_InfiniteNoMessage(t *testing.T) {
	// Setup
	bar, channel := setupTestLSProgressBar(t)

	// Test
	updateProgressAndAssertExpected(t, bar, channel, "", false, ui.InfiniteProgress)

	// Sleep to prevent hitting the Tracker's anti-spam, since this is an odd use-case.
	time.Sleep(time.Millisecond * 200)

	updateProgressAndAssertExpected(t, bar, channel, "", true, ui.InfiniteProgress)

	clearAndAssertProgressEnd(t, bar, channel)
}

func Test_ProgressBar_Handles_NoUpdates(t *testing.T) {
	// Setup
	bar, channel := setupTestLSProgressBar(t)

	// Test
	// Action
	err := bar.Clear()

	// Assertions
	assert.NoError(t, err)

	testsupport.AssertChannelIsEmpty(t, channel)
}

func Test_ProgressBar_Handles_OnlyMessageNoProgress(t *testing.T) {
	// Setup
	bar, channel := setupTestLSProgressBar(t)

	// Test
	setMessageAndAssertExpected(t, bar, channel, nil, "I don't know how to use this...")
	err := bar.Clear()
	assert.NoError(t, err)
	testsupport.AssertChannelIsEmpty(t, channel)
}

func Test_ProgressBar_HandlesIncorrectUsage_UseAfterClear(t *testing.T) {
	// Setup
	bar, channel := setupTestLSProgressBar(t)

	updateProgressAndAssertExpected(t, bar, channel, "", false, 0)

	clearAndAssertProgressEnd(t, bar, channel)

	// Test
	// Action
	err := updateProgress(t, bar, 0.5)

	// Assertions
	assert.NoError(t, err)

	testsupport.AssertChannelIsEmpty(t, channel)
}

func Test_ProgressBar_Handles_Over100Percent(t *testing.T) {
	// Setup
	bar, channel := setupTestLSProgressBar(t)

	updateProgressAndAssertExpected(t, bar, channel, "", false, 0)

	// Test
	updateProgressAndAssertExpected(t, bar, channel, "", true, 1.2)

	// Teardown
	clearAndAssertProgressEnd(t, bar, channel)
}
