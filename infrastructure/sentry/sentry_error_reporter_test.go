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

package sentry

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"

	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

func TestErrorReporting_CaptureError(t *testing.T) {
	engine := testutil.UnitTest(t)
	e := errors.New("test error")
	channel := make(chan sglsp.ShowMessageParams)
	notifier := notification.NewNotifier()
	notifier.CreateListener(func(params any) {
		switch p := params.(type) {
		case sglsp.ShowMessageParams:
			channel <- p
		default:
			engine.GetLogger().Debug().Msgf("Unexpected notification: %v", params)
			return
		}
	})
	var target = NewSentryErrorReporter(engine.GetConfiguration(), engine.GetLogger(), engine, notifier, testutil.DefaultConfigResolver(engine))

	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSendErrorReports), false)
	captured := target.CaptureError(e)
	assert.False(t, captured)

	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSendErrorReports), true)
	captured = target.CaptureError(e)
	assert.True(t, captured)

	showMessageParams := <-channel
	assert.Equal(t, "Snyk encountered an error: test error", showMessageParams.Message)
}

func TestErrorReporting_CaptureError_IgnoresCancellation(t *testing.T) {
	engine := testutil.UnitTest(t)
	channel := make(chan sglsp.ShowMessageParams, 1)
	notifier := notification.NewNotifier()
	notifier.CreateListener(func(params any) {
		if p, ok := params.(sglsp.ShowMessageParams); ok {
			channel <- p
		}
	})
	var target = NewSentryErrorReporter(engine.GetConfiguration(), engine.GetLogger(), engine, notifier, testutil.DefaultConfigResolver(engine))

	// Error reporting is enabled, so only the cancellation guard can suppress the report.
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSendErrorReports), true)

	// Both a bare and a wrapped cancellation (e.g. "signal: killed" normalized to context.Canceled,
	// then wrapped by getToken) must be treated as a non-error.
	for _, err := range []error{context.Canceled, fmt.Errorf("error getting creds: %w", context.Canceled)} {
		captured := target.CaptureError(err)
		assert.False(t, captured, "cancellation must not be reported to Sentry")
	}

	select {
	case msg := <-channel:
		t.Fatalf("cancellation must not notify the user, got: %q", msg.Message)
	case <-time.After(100 * time.Millisecond):
		// no notification delivered — expected
	}
}

func TestErrorReporting_CaptureError_NilNotifier_DoesNotPanic(t *testing.T) {
	engine := testutil.UnitTest(t)
	// Reporting disabled so sendToSentry is a no-op; this only exercises the nil-notifier guard.
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSendErrorReports), false)
	var target = NewSentryErrorReporter(engine.GetConfiguration(), engine.GetLogger(), engine, nil, testutil.DefaultConfigResolver(engine))

	assert.NotPanics(t, func() {
		captured := target.CaptureError(errors.New("boom"))
		assert.False(t, captured)
	})
}

func TestErrorReporting_CaptureErrorAndReportAsIssue_IgnoresCancellation(t *testing.T) {
	engine := testutil.UnitTest(t)
	path := types.FilePath("testPath")
	channel := make(chan types.PublishDiagnosticsParams, 1)
	notifier := notification.NewNotifier()
	notifier.CreateListener(func(params any) {
		if p, ok := params.(types.PublishDiagnosticsParams); ok {
			channel <- p
		}
	})
	var target = NewSentryErrorReporter(engine.GetConfiguration(), engine.GetLogger(), engine, notifier, testutil.DefaultConfigResolver(engine))

	// Error reporting is enabled, so only the cancellation guard can suppress the report.
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSendErrorReports), true)

	// Both a bare and a wrapped cancellation must be treated as a non-error.
	for _, err := range []error{context.Canceled, fmt.Errorf("error getting creds: %w", context.Canceled)} {
		captured := target.CaptureErrorAndReportAsIssue(path, err)
		assert.False(t, captured, "cancellation must not be reported to Sentry")
	}

	select {
	case diag := <-channel:
		t.Fatalf("cancellation must not publish a diagnostic, got: %q", diag.Diagnostics[0].Message)
	case <-time.After(100 * time.Millisecond):
		// no diagnostic delivered — expected
	}
}

func TestErrorReporting_CaptureErrorAndReportAsIssue(t *testing.T) {
	engine := testutil.UnitTest(t)
	path := types.FilePath("testPath")
	text := "test error"
	channel := make(chan types.PublishDiagnosticsParams)
	notifier := notification.NewNotifier()
	notifier.CreateListener(func(params any) {
		switch p := params.(type) {
		case types.PublishDiagnosticsParams:
			channel <- p
		default:
			engine.GetLogger().Debug().Msgf("Unexpected notification: %v", params)
			return
		}
	})
	var target = NewSentryErrorReporter(engine.GetConfiguration(), engine.GetLogger(), engine, notifier, testutil.DefaultConfigResolver(engine))

	e := errors.New(text)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSendErrorReports), false)
	captured := target.CaptureErrorAndReportAsIssue(path, e)
	assert.False(t, captured)

	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingSendErrorReports), true)
	captured = target.CaptureErrorAndReportAsIssue(path, e)
	assert.True(t, captured)

	diagnosticsParams := <-channel
	assert.Equal(t, text, diagnosticsParams.Diagnostics[0].Message)
	assert.Equal(t, types.DiagnosticsSeverityWarning, diagnosticsParams.Diagnostics[0].Severity)
	assert.Equal(t, diagnosticsParams.URI, uri.PathToUri(path))
	assert.Equal(t, diagnosticsParams.Diagnostics[0].CodeDescription.Href, types.Uri("https://snyk.io/user-hub"))
}
