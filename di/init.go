package di

import (
	"sync"
	"testing"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/code"
	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/infrastructure/segment"
	"github.com/snyk/snyk-ls/internal/observability/infrastructure/sentry"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/observability/ux"
)

var snykApiClient code.SnykApiClient
var snykCodeClient code.SnykCodeClient
var snykCodeBundleUploader *code.BundleUploader
var snykCode *code.SnykCode

var instrumentor performance.Instrumentor
var errorReporter error_reporting.ErrorReporter
var analytics ux.Analytics

var initMutex = &sync.Mutex{}

func Init() {
	initMutex.Lock()
	defer initMutex.Unlock()
	initInfrastructure()
	initApplication()
}

func initApplication() {
	snykCode = code.NewSnykCode(snykCodeBundleUploader, snykApiClient, errorReporter, analytics)
}

func initInfrastructure() {
	errorReporter = sentry.NewSentryErrorReporter()
	endpoint := config.CurrentConfig().CliSettings().Endpoint
	if endpoint == "" {
		endpoint = code.DefaultEndpointURL
	}
	snykApiClient = code.NewSnykApiClient(endpoint)
	instrumentor = sentry.NewInstrumentor()
	user, err := snykApiClient.GetActiveUser()
	if err != nil {
		log.Warn().Err(err).Msg("Error retrieving current user")
	}
	if err != nil || user.Id == "" {
		errorReporter.CaptureError(errors.Wrap(err, "cannot retrieve active user, configuring noop analytics"))
		analytics = ux.NewNoopRecordingClient()
	}
	analytics = segment.NewSegmentClient(user.Id, ux.Eclipse)
	snykCodeClient = code.NewHTTPRepository(config.CurrentConfig().SnykCodeApi(), instrumentor, errorReporter)
	snykCodeBundleUploader = code.NewBundler(snykCodeClient, instrumentor)
}

//TODO move out of prod logic
func TestInit(t *testing.T) {
	initMutex.Lock()
	defer initMutex.Unlock()
	t.Helper()
	analytics = ux.NewNoopRecordingClient()
	instrumentor = &performance.TestInstrumentor{}
	errorReporter = sentry.NewTestErrorReporter()
	fakeClient := &code.FakeSnykCodeClient{}
	snykCodeClient = fakeClient
	snykCodeBundleUploader = code.NewBundler(snykCodeClient, instrumentor)
	fakeApiClient := &code.FakeApiClient{CodeEnabled: true}
	snykCode = code.NewSnykCode(snykCodeBundleUploader, fakeApiClient, errorReporter, analytics)
	t.Cleanup(func() {
		fakeClient.Clear()
	})
}

/*
Accessors: This should go away, since all dependencies should be satisfied at startup-time
*/

func Instrumentor() performance.Instrumentor {
	initMutex.Lock()
	defer initMutex.Unlock()
	return instrumentor
}

func Analytics() ux.Analytics {
	initMutex.Lock()
	defer initMutex.Unlock()
	return analytics
}

func ErrorReporter() error_reporting.ErrorReporter {
	initMutex.Lock()
	defer initMutex.Unlock()
	return errorReporter
}

func SnykCode() *code.SnykCode {
	initMutex.Lock()
	defer initMutex.Unlock()
	return snykCode
}

func SnykCodeClient() code.SnykCodeClient {
	initMutex.Lock()
	defer initMutex.Unlock()
	return snykCodeClient
}
