package progress

import (
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/server/lsp"
)

var Channel = make(chan lsp.ProgressParams, 100)
var CancelProgressChannel = make(chan lsp.ProgressToken, 100)

type Tracker struct {
	channel       chan lsp.ProgressParams
	cancelChannel chan lsp.ProgressToken
	token         lsp.ProgressToken
	cancellable   bool
	lastReport    time.Time
	finished      bool
}

func NewTestTracker(channel chan lsp.ProgressParams, cancelChannel chan lsp.ProgressToken) *Tracker {
	return &Tracker{
		channel:       channel,
		cancelChannel: cancelChannel,
		// deepcode ignore HardcodedPassword: false positive
		token:       "token",
		cancellable: true,
	}
}

func NewTracker(cancellable bool) *Tracker {
	return &Tracker{
		channel:       Channel,
		cancelChannel: CancelProgressChannel,
		cancellable:   cancellable,
		finished:      false,
	}
}

func (t *Tracker) BeginUnquantifiableLength(title, message string) {
	// 0 is interpreted by Eclipse as unquantified
	t.begin(title, message, true)
}

func (t *Tracker) begin(title string, message string, unquantifiableLength bool) {
	params := newProgressParams(title, message, t.cancellable, unquantifiableLength)
	t.token = params.Token

	t.send(lsp.ProgressParams{
		Token: t.token,
		Value: nil,
	})

	t.send(params)
	t.lastReport = time.Now()
}

func (t *Tracker) Begin(title, message string) {
	t.begin(title, message, false)
}

func (t *Tracker) Report(percentage int) {
	if time.Now().Before(t.lastReport.Add(time.Second)) {
		return
	}
	progress := lsp.ProgressParams{
		Token: t.token,
		Value: lsp.WorkDoneProgressReport{
			WorkDoneProgressKind: lsp.WorkDoneProgressKind{Kind: "report"},
			Percentage:           percentage,
		},
	}
	t.send(progress)
	t.lastReport = time.Now()
}

func (t *Tracker) End(message string) {
	if t.finished {
		panic("Called end progress twice. This breaks LSP in Eclipse fix me now and avoid headaches later")
	}
	t.finished = true
	progress := lsp.ProgressParams{
		Token: t.token,
		Value: lsp.WorkDoneProgressEnd{
			WorkDoneProgressKind: lsp.WorkDoneProgressKind{Kind: "end"},
			Message:              message,
		},
	}

	t.send(progress)
}
func (t *Tracker) CancelOrDone(onCancel func(), doneCh chan bool) {
	for {
		select {
		case token := <-t.cancelChannel:
			if token == t.token {
				onCancel()
			}
		case <-doneCh:
			return
		}
	}
}

func (t *Tracker) GetToken() lsp.ProgressToken {
	return t.token
}

func newProgressParams(title, message string, cancellable, unquantifiableLength bool) lsp.ProgressParams {
	id := uuid.New().String()
	percentage := 1
	if unquantifiableLength {
		percentage = 0
	}
	return lsp.ProgressParams{
		Token: lsp.ProgressToken(id),
		Value: lsp.WorkDoneProgressBegin{
			WorkDoneProgressKind: lsp.WorkDoneProgressKind{Kind: "begin"},
			Title:                title,
			Message:              message,
			Cancellable:          cancellable,
			Percentage:           percentage,
		},
	}
}

func (t *Tracker) send(progress lsp.ProgressParams) {
	if progress.Token == "" {
		log.Error().Str("method", "EndProgress").Msg("progress token must be set")
	}
	t.channel <- progress
}
