/*
 * © 2026 Snyk Limited All rights reserved.
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

package workspace

import (
	stderrors "errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cli_errors "github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"

	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// IDE-1668: emit failure analytics when a scan returns an error.
//
// These tests cover the contract: sendAnalytics() must produce a
// `interaction.status:"Failure"` event with `error_category` (catalog prefix,
// e.g. "SNYK-CLI") and, when available, `error_code` (full catalog code).
// The empty-product and SendAnalytics=false guards must continue to suppress
// emission even on the failure path.

// T1 — failed scan whose error wraps a snyk catalog entry produces a Failure
// analytics event with the full error code and its product prefix.
func Test_processResults_FailedScan_EmitsFailureAnalytics_WithCatalogError(t *testing.T) {
	engine := testutil.UnitTest(t)
	engineMock, engineConfig := testutil.SetUpEngineMock(t, engine)
	engineMock.EXPECT().GetWorkflows().AnyTimes()

	notifier := notification.NewNotifier()
	f, _ := NewMockFolderWithScanNotifier(engineMock, notifier)
	setupWorkspaceWithFolder(engineMock, f, notifier)

	const testFolderOrg = "test-org"
	types.SetPreferredOrgAndOrgSetByUser(engineConfig, f.path, testFolderOrg, true)

	catalogErr := cli_errors.NewNoSupportedFilesFoundError("nothing to scan")

	data := types.ScanData{
		Product:           product.ProductOpenSource,
		Path:              f.path,
		UpdateGlobalCache: true,
		SendAnalytics:     true,
		Err:               catalogErr,
	}

	capturedCh := testutil.MockAndCaptureWorkflowInvocation(t, engineMock, localworkflows.WORKFLOWID_REPORT_ANALYTICS, 1)

	f.ProcessResults(t.Context(), data)

	captured := testsupport.RequireEventuallyReceive(t, capturedCh, time.Second, 10*time.Millisecond, "failure analytics should have been sent")
	require.Len(t, captured.Input, 1)
	payload := string(captured.Input[0].GetPayload().([]byte))

	assert.Contains(t, payload, `"status":"failure"`, "interaction.status should be failure on errored scan")
	assert.Contains(t, payload, `"error_category":"SNYK-CLI"`, "error_category should be the catalog prefix")
	// NewNoSupportedFilesFoundError maps to SNYK-CLI-0008 (see infrastructure/secrets/errors.go).
	assert.Contains(t, payload, `"error_code":"SNYK-CLI-0008"`, "error_code should be the full catalog code")
}

// T2 — failed scan whose error is NOT a catalog entry produces a Failure event
// with error_category:"unknown" and no error_code field.
func Test_processResults_FailedScan_EmitsFailureAnalytics_WithNonCatalogError(t *testing.T) {
	engine := testutil.UnitTest(t)
	engineMock, engineConfig := testutil.SetUpEngineMock(t, engine)
	engineMock.EXPECT().GetWorkflows().AnyTimes()

	notifier := notification.NewNotifier()
	f, _ := NewMockFolderWithScanNotifier(engineMock, notifier)
	setupWorkspaceWithFolder(engineMock, f, notifier)

	const testFolderOrg = "test-org"
	types.SetPreferredOrgAndOrgSetByUser(engineConfig, f.path, testFolderOrg, true)

	data := types.ScanData{
		Product:           product.ProductOpenSource,
		Path:              f.path,
		UpdateGlobalCache: true,
		SendAnalytics:     true,
		Err:               stderrors.New("boom"),
	}

	capturedCh := testutil.MockAndCaptureWorkflowInvocation(t, engineMock, localworkflows.WORKFLOWID_REPORT_ANALYTICS, 1)

	f.ProcessResults(t.Context(), data)

	captured := testsupport.RequireEventuallyReceive(t, capturedCh, time.Second, 10*time.Millisecond, "failure analytics should have been sent")
	require.Len(t, captured.Input, 1)
	payload := string(captured.Input[0].GetPayload().([]byte))

	assert.Contains(t, payload, `"status":"failure"`)
	assert.Contains(t, payload, `"error_category":"unknown"`)
	assert.NotContains(t, payload, `"error_code"`, "non-catalog errors must not produce an error_code field")
}

// T3 — successful scan continues to emit Success and must not pick up
// error_category / error_code in the extension. Regression guard.
func Test_processResults_SuccessfulScan_StillEmitsSuccessAnalytics(t *testing.T) {
	engine := testutil.UnitTest(t)
	engineMock, engineConfig := testutil.SetUpEngineMock(t, engine)
	engineMock.EXPECT().GetWorkflows().AnyTimes()

	notifier := notification.NewNotifier()
	f, _ := NewMockFolderWithScanNotifier(engineMock, notifier)
	setupWorkspaceWithFolder(engineMock, f, notifier)

	const testFolderOrg = "test-org"
	types.SetPreferredOrgAndOrgSetByUser(engineConfig, f.path, testFolderOrg, true)

	data := types.ScanData{
		Product:           product.ProductOpenSource,
		Path:              f.path,
		UpdateGlobalCache: true,
		SendAnalytics:     true,
	}

	capturedCh := testutil.MockAndCaptureWorkflowInvocation(t, engineMock, localworkflows.WORKFLOWID_REPORT_ANALYTICS, 1)

	f.ProcessResults(t.Context(), data)

	captured := testsupport.RequireEventuallyReceive(t, capturedCh, time.Second, 10*time.Millisecond, "success analytics should have been sent")
	require.Len(t, captured.Input, 1)
	payload := string(captured.Input[0].GetPayload().([]byte))

	assert.Contains(t, payload, `"status":"success"`)
	assert.NotContains(t, payload, `"error_category"`, "success events must not carry error_category")
	assert.NotContains(t, payload, `"error_code"`, "success events must not carry error_code")
}

// T4 — when Product is empty, the empty-product guard suppresses emission
// even though data.Err is set. Suppressing this branch keeps existing behavior.
func Test_processResults_FailedScan_EmptyProduct_NoEmission(t *testing.T) {
	engine := testutil.UnitTest(t)
	engineMock, engineConfig := testutil.SetUpEngineMock(t, engine)
	engineMock.EXPECT().GetWorkflows().AnyTimes()

	notifier := notification.NewNotifier()
	f, _ := NewMockFolderWithScanNotifier(engineMock, notifier)
	setupWorkspaceWithFolder(engineMock, f, notifier)

	const testFolderOrg = "test-org"
	types.SetPreferredOrgAndOrgSetByUser(engineConfig, f.path, testFolderOrg, true)

	data := types.ScanData{
		Product:           "",
		Path:              f.path,
		UpdateGlobalCache: true,
		SendAnalytics:     true,
		Err:               stderrors.New("boom"),
	}

	// Times(0) — gomock will fail the test if the analytics workflow gets invoked.
	_ = testutil.MockAndCaptureWorkflowInvocation(t, engineMock, localworkflows.WORKFLOWID_REPORT_ANALYTICS, 0)

	f.ProcessResults(t.Context(), data)

	// Small settle window so any (incorrect) async emission would have time to land.
	time.Sleep(50 * time.Millisecond)
}

// T5 — when SendAnalytics is false, the caller opt-out must continue to
// suppress emission even with an error present.
func Test_processResults_FailedScan_SendAnalyticsFalse_NoEmission(t *testing.T) {
	engine := testutil.UnitTest(t)
	engineMock, engineConfig := testutil.SetUpEngineMock(t, engine)
	engineMock.EXPECT().GetWorkflows().AnyTimes()

	notifier := notification.NewNotifier()
	f, _ := NewMockFolderWithScanNotifier(engineMock, notifier)
	setupWorkspaceWithFolder(engineMock, f, notifier)

	const testFolderOrg = "test-org"
	types.SetPreferredOrgAndOrgSetByUser(engineConfig, f.path, testFolderOrg, true)

	data := types.ScanData{
		Product:           product.ProductOpenSource,
		Path:              f.path,
		UpdateGlobalCache: true,
		SendAnalytics:     false,
		Err:               stderrors.New("boom"),
	}

	_ = testutil.MockAndCaptureWorkflowInvocation(t, engineMock, localworkflows.WORKFLOWID_REPORT_ANALYTICS, 0)

	f.ProcessResults(t.Context(), data)

	time.Sleep(50 * time.Millisecond)
}

// T6 — sendAnalytics must tolerate partial ScanData on the failure path
// (no Issues, no severity counts). It must emit a Failure event without
// panicking and the test summary should at least contain the product type.
func Test_processResults_FailedScan_PartialScanData_DoesNotPanic(t *testing.T) {
	engine := testutil.UnitTest(t)
	engineMock, engineConfig := testutil.SetUpEngineMock(t, engine)
	engineMock.EXPECT().GetWorkflows().AnyTimes()

	notifier := notification.NewNotifier()
	f, _ := NewMockFolderWithScanNotifier(engineMock, notifier)
	setupWorkspaceWithFolder(engineMock, f, notifier)

	const testFolderOrg = "test-org"
	types.SetPreferredOrgAndOrgSetByUser(engineConfig, f.path, testFolderOrg, true)

	// Deliberately minimal ScanData: nil Issues, zero Duration, etc.
	data := types.ScanData{
		Product:       product.ProductOpenSource,
		Path:          f.path,
		SendAnalytics: true,
		Err:           snyk_errors.Error{ErrorCode: "SNYK-OS-7001", Title: "Request timeout"},
	}

	capturedCh := testutil.MockAndCaptureWorkflowInvocation(t, engineMock, localworkflows.WORKFLOWID_REPORT_ANALYTICS, 1)

	// Must not panic.
	require.NotPanics(t, func() {
		f.ProcessResults(t.Context(), data)
	})

	captured := testsupport.RequireEventuallyReceive(t, capturedCh, time.Second, 10*time.Millisecond, "failure analytics should still be emitted on partial scan data")
	require.Len(t, captured.Input, 1)
	payload := string(captured.Input[0].GetPayload().([]byte))

	assert.Contains(t, payload, `"status":"failure"`)
	assert.Contains(t, payload, `"error_category":"SNYK-OS"`)
	assert.Contains(t, payload, `"error_code":"SNYK-OS-7001"`)
}
