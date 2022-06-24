package di

import (
	"sync"
	"testing"

	"github.com/pkg/errors"

	"github.com/snyk/snyk-ls/code"
	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/cli"
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
var snykCli cli.Executor

var hoverService *hover.Service
var scanner snyk.Scanner

var initMutex = &sync.Mutex{}

func Init() {
	initMutex.Lock()
	defer initMutex.Unlock()
	initInfrastructure()
	initDomain()
	initApplication()
}

func initApplication() {
	snykCode = code.NewSnykCode(snykCodeBundleUploader, snykApiClient, errorReporter, analytics)
}

func initDomain() {
	hoverService = hover.NewService(analytics)
	scanner = snyk.NewDefaultScanner(snykCli, instrumentor, analytics)
}

func initInfrastructure() {
	snykCli = cli.NewExecutor()
	errorReporter = sentry.NewSentryErrorReporter()
	endpoint := config.CurrentConfig().CliSettings().Endpoint
	if endpoint == "" {
		endpoint = code.DefaultEndpointURL
	}
	snykApiClient = code.NewSnykApiClient(endpoint)
	instrumentor = sentry.NewInstrumentor()
	snykCodeClient = code.NewHTTPRepository(config.CurrentConfig().SnykCodeApi(), instrumentor, errorReporter)
	snykCodeBundleUploader = code.NewBundler(snykCodeClient, instrumentor)
}

func InitializeAnalytics() {
	user, err := snykApiClient.GetActiveUser()
	if err != nil || user.Id == "" {
		if err == nil {
			err = errors.New("cannot retrieve active user, configuring noop analytics")
		} else {
			err = errors.Wrap(err, "cannot retrieve active user, configuring noop analytics")
		}
		errorReporter.CaptureError(err)
		analytics = ux.NewNoopRecordingClient()
	} else {
		analytics = segment.NewSegmentClient(user.Id, ux.Eclipse) // FIXME: Don't hardcode Eclipse here
	}
	// FIXME: we need to initialize analytics differently
	snykCode.SetAnalytics(analytics)
	hoverService.SetAnalytics(analytics)
}

//TODO move out of prod logic
func TestInit(t *testing.T) {
	initMutex.Lock()
	defer initMutex.Unlock()
	t.Helper()
	hoverService = hover.NewService(analytics)
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
TODO Accessors: This should go away, since all dependencies should be satisfied at startup-time, if needed for testing
they can be returned by the test helper for unit/integration tests
*/

func Instrumentor() performance.Instrumentor {
	initMutex.Lock()
	defer initMutex.Unlock()
	return instrumentor
}

func Analytics() ux.Analytics {
	initMutex.Lock()
	defer initMutex.Unlock()
	if analytics == nil {
		InitializeAnalytics()
	}
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

func HoverService() *hover.Service {
	initMutex.Lock()
	defer initMutex.Unlock()
	return hoverService
}

func Scanner() snyk.Scanner {
	initMutex.Lock()
	defer initMutex.Unlock()
	return scanner
}
