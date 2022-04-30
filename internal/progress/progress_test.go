package progress

import (
	"testing"

	"github.com/snyk/snyk-ls/lsp"
	"github.com/stretchr/testify/assert"
)

func TestCreateProgress(t *testing.T) {
	title := "title"
	message := "message"
	cancellable := true

	p := New(title, message, cancellable)

	assert.NotNil(t, p)
	assert.NotEqual(t, "", p.Token)

	workProgressBegin := p.Value.(lsp.WorkDoneProgressBegin)
	assert.Equal(t, "begin", workProgressBegin.Kind)
	assert.Equal(t, title, workProgressBegin.Title)
	assert.Equal(t, message, workProgressBegin.Message)
	assert.Equal(t, uint32(0), workProgressBegin.Percentage)
}

func TestBeginProgress(t *testing.T) {
	title := "title"
	message := "message"
	cancellable := true

	progress := New(title, message, cancellable)
	channel := make(chan lsp.ProgressParams, 2)

	BeginProgress(progress, channel) // todo: do we need to pass channel here? why not to use ProgressChannel?

	assert.Equal(t, lsp.ProgressParams{
		Token: progress.Token,
	}, <-channel)
	assert.Equal(t, progress, <-channel)
}

func TestReportProgress(t *testing.T) {
	progress := lsp.ProgressParams{
		Token: "token",
		Value: lsp.WorkDoneProgressReport{
			WorkDoneProgressKind: lsp.WorkDoneProgressKind{Kind: "report"},
			Percentage:           10,
		},
	}
	channel := make(chan lsp.ProgressParams, 1)

	workProgressReport := progress.Value.(lsp.WorkDoneProgressReport)
	ReportProgress(progress.Token, workProgressReport.Percentage, channel)

	assert.Equal(t, progress, <-channel)
}

func TestEndProgress(t *testing.T) {
	progress := lsp.ProgressParams{
		Token: "token",
		Value: lsp.WorkDoneProgressEnd{
			WorkDoneProgressKind: lsp.WorkDoneProgressKind{Kind: "end"},
			Message:              "end message",
		},
	}
	channel := make(chan lsp.ProgressParams, 1)

	workProgressEnd := progress.Value.(lsp.WorkDoneProgressEnd)
	EndProgress(progress.Token, workProgressEnd.Message, channel)

	assert.Equal(t, progress, <-channel)
}

func TestSendProgress(t *testing.T) {
	progress := lsp.ProgressParams{
		Token: "token",
		Value: lsp.WorkDoneProgressBegin{
			WorkDoneProgressKind: lsp.WorkDoneProgressKind{Kind: "begin"},
			Title:                "title",
			Message:              "message",
			Cancellable:          true,
			Percentage:           0,
		},
	}
	channel := make(chan lsp.ProgressParams, 1)

	send(progress, channel)

	assert.Equal(t, progress, <-channel)
}

func TestReadProgress(t *testing.T) {
	progress := lsp.ProgressParams{
		Token: "token",
		Value: lsp.WorkDoneProgressBegin{
			WorkDoneProgressKind: lsp.WorkDoneProgressKind{Kind: "begin"},
			Title:                "title",
			Message:              "message",
			Cancellable:          true,
			Percentage:           0,
		},
	}
	channel := make(chan lsp.ProgressParams, 1)
	channel <- progress

	p := readProgress(channel)

	assert.Equal(t, progress, p)
}
