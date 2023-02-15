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
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/server/lsp"
)

type Tracker struct {
	token                lsp.ProgressToken
	cancellable          bool
	lastReport           time.Time
	lastReportPercentage int
	finished             bool
}

func NewTestTracker() *Tracker {
	return &Tracker{
		// deepcode ignore HardcodedPassword: false positive
		token:                "token",
		cancellable:          true,
		lastReportPercentage: -1,
	}
}

func NewTracker(cancellable bool) *Tracker {
	return &Tracker{
		cancellable: cancellable,
		finished:    false,
	}
}

func (t *Tracker) BeginUnquantifiableLength(title, message string) {
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

func (t *Tracker) ReportWithMessage(percentage int, message string) {
	if time.Now().Before(t.lastReport.Add(time.Second)) || percentage <= t.lastReportPercentage {
		return
	}
	progress := lsp.ProgressParams{
		Token: t.token,
		Value: lsp.WorkDoneProgressReport{
			WorkDoneProgressKind: lsp.WorkDoneProgressKind{Kind: "report"},
			Percentage:           percentage,
			Message:              message,
		},
	}
	t.send(progress)
	t.lastReport = time.Now()
	t.lastReportPercentage = percentage
}

func (t *Tracker) Report(percentage int) {
	t.ReportWithMessage(percentage, "")
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
	ProgressReported.Raise(progress)
}

var ProgressReported progressReported

type ProgressHandler interface {
	Handle(lsp.ProgressParams)
}

type progressReported struct {
	handlers []ProgressHandler
}

// Subscribe adds an event handler for this event
func (pr *progressReported) Subscribe(handler ProgressHandler) {
	pr.handlers = append(pr.handlers, handler)
}

// Trigger sends out an event with the payload
func (pr *progressReported) Raise(payload lsp.ProgressParams) {
	for _, handler := range pr.handlers {
		handler.Handle(payload)
	}
}

var ProgressCancelled progressCancelled

type ProgressCancelledHandler interface {
	Handle(lsp.ProgressToken)
}
type progressCancelled struct {
	handlers map[string]ProgressCancelledHandler
}

// Subscribe adds an event handler for this event
func (pr *progressCancelled) Subscribe(handler ProgressCancelledHandler) (handlerId string) {
	if pr.handlers == nil {
		pr.handlers = make(map[string]ProgressCancelledHandler)
	}

	handlerId = uuid.New().String()
	pr.handlers[handlerId] = handler
	return handlerId
}

// Subscribe adds an event handler for this event
func (pr *progressCancelled) Unsubscribe(handlerId string) {
	delete(pr.handlers, handlerId)
}

// Trigger sends out an event with the payload
func (pr *progressCancelled) Raise(payload lsp.ProgressToken) {
	for _, handler := range pr.handlers {
		handler.Handle(payload)
	}
}

type CancelNotifier struct {
	Token     lsp.ProgressToken
	CallBack  func(handlerId string)
	HandlerId string
}

func (c *CancelNotifier) Handle(token lsp.ProgressToken) {
	if token == c.Token {
		c.CallBack(c.HandlerId)
	}
}
