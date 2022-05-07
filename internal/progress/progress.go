package progress

import (
	"context"

	"github.com/google/uuid"

	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/lsp"
)

var Channel = make(chan lsp.ProgressParams, 100)
var CancelProgressChannel = make(chan lsp.ProgressToken, 100)
var logger = environment.Logger

func New(title, message string, cancellable bool) lsp.ProgressParams {
	u := uuid.New().String()

	return lsp.ProgressParams{
		Token: lsp.ProgressToken(u),
		Value: lsp.WorkDoneProgressBegin{
			WorkDoneProgressKind: lsp.WorkDoneProgressKind{Kind: "begin"},
			Title:                title,
			Message:              message,
			Cancellable:          cancellable,
			Percentage:           0,
		},
	}
}

func BeginProgress(progress lsp.ProgressParams, channel chan lsp.ProgressParams) {
	send(lsp.ProgressParams{
		Token: progress.Token,
		Value: nil,
	}, channel)

	send(progress, channel)
}

func ReportProgress(token lsp.ProgressToken, percentage uint32, channel chan lsp.ProgressParams) {
	progress := lsp.ProgressParams{
		Token: token,
		Value: lsp.WorkDoneProgressReport{
			WorkDoneProgressKind: lsp.WorkDoneProgressKind{Kind: "report"},
			Percentage:           percentage,
		},
	}

	send(progress, channel)
}

func EndProgress(token lsp.ProgressToken, message string, channel chan lsp.ProgressParams) {
	progress := lsp.ProgressParams{
		Token: token,
		Value: lsp.WorkDoneProgressEnd{
			WorkDoneProgressKind: lsp.WorkDoneProgressKind{Kind: "end"},
			Message:              message,
		},
	}

	send(progress, channel)
}

func send(progress lsp.ProgressParams, channel chan lsp.ProgressParams) {
	if progress.Token == "" {
		logger.
			WithField("method", "send").
			Error(context.Background(), "progress token must be set")
	}

	channel <- progress
}

func readProgress(channel chan lsp.ProgressParams) lsp.ProgressParams {
	return <-channel
}
