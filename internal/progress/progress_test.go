package progress

import (
	"testing"

	"github.com/snyk/snyk-ls/presentation/lsp"

	"github.com/stretchr/testify/assert"
)

func TestBeginProgress(t *testing.T) {
	channel := make(chan lsp.ProgressParams, 2)
	progress := NewTestingTracker(channel, nil)

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
	progress := NewTestingTracker(channel, nil)

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
	progress := NewTestingTracker(channel, nil)

	workProgressEnd := output.Value.(lsp.WorkDoneProgressEnd)
	progress.End(workProgressEnd.Message)

	assert.Equal(t, output, <-channel)
}
