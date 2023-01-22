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

package notification

import (
	"fmt"

	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/internal/uri"

	sglsp "github.com/sourcegraph/go-lsp"
)

var channel = make(chan any, 100)
var stopChannel = make(chan bool, 1000)

func SendShowMessage(messageType sglsp.MessageType, message string) {
	channel <- sglsp.ShowMessageParams{Type: messageType, Message: message}
}

func Send(msg any) {
	channel <- msg
}

func SendError(err error) {
	Send(sglsp.ShowMessageParams{
		Type:    sglsp.MTError,
		Message: fmt.Sprintf("Snyk encountered an error: %v", err),
	})
}

func SendErrorDiagnostic(path string, err error) {
	Send(lsp.PublishDiagnosticsParams{
		URI: uri.PathToUri(path),
		Diagnostics: []lsp.Diagnostic{{
			Range:           sglsp.Range{},
			Severity:        lsp.DiagnosticsSeverityWarning,
			Code:            "Snyk Error",
			CodeDescription: lsp.CodeDescription{Href: "https://snyk.io/user-hub"},
			Message:         err.Error(),
		}},
	})
}

func Receive() (payload any, stop bool) {
	select {
	case payload = <-channel:
		return payload, false
	case <-stopChannel:
		return payload, true
	}
}

func CreateListener(callback func(params any)) {
	// cleanup stopchannel before starting
	for {
		select {
		case <-stopChannel:
			continue
		default:
			break
		}
		break
	}
	go func() {
		for {
			payload, stop := Receive()
			if stop {
				break
			}
			callback(payload)
		}
	}()
}

func DisposeListener() {
	stopChannel <- true
}
