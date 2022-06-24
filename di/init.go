package di

import (
	"sync"
	"testing"

	"github.com/pkg/errors"

	"github.com/snyk/snyk-ls/code"
	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/iac"
	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/internal/cli/auth"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/infrastructure/segment"
	"github.com/snyk/snyk-ls/internal/observability/infrastructure/sentry"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/observability/ux"
	"github.com/snyk/snyk-ls/internal/preconditions"
	"github.com/snyk/snyk-ls/oss"
)

var snykApiClient code.SnykApiClient
var snykCodeClient code.SnykCodeClient
var snykCodeBundleUploader *code.BundleUploader
var snykCodeScanner *code.Scanner
var infrastructureAsCodeScanner *iac.Scanner
var openSourceScanner *oss.Scanner
var environmentInitializer *preconditions.EnvironmentInitializer
var authenticator *auth.Authenticator

var instrumentor performance.Instrumentor
var errorReporter error_reporting.ErrorReporter
var analytics ux.Analytics
var snykCli cli.Executor

var hoverService hover.Service
var scanner snyk.Scanner

var initMutex = &sync.Mutex{}

func Init() {
	initMutex.Lock()
	defer initMutex.Unlock()
	initInfrastructure()
	initDomain()
}

func initDomain() {
	hoverService = hover.NewDefaultService(analytics)
	scanner = snyk.NewDefaultScanner(
		snykCodeScanner,
		infrastructureAsCodeScanner,
		openSourceScanner,
		environmentInitializer,
		instrumentor,
		analytics,
	)
}

func initInfrastructure() {
	errorReporter = sentry.NewSentryErrorReporter()
	instrumentor = sentry.NewInstrumentor()
	endpoint := config.CurrentConfig().CliSettings().Endpoint
	if endpoint == "" {
		endpoint = code.DefaultEndpointURL
	}
	snykApiClient = code.NewSnykApiClient(endpoint)
	analytics = analyticsFactory(snykApiClient)
	authenticator = auth.New(errorReporter)
	snykCli = cli.NewExecutor(authenticator)
	snykCodeClient = code.NewHTTPRepository(config.CurrentConfig().SnykCodeApi(), instrumentor, errorReporter)
	snykCodeBundleUploader = code.NewBundler(snykCodeClient, instrumentor)
	infrastructureAsCodeScanner = iac.New(instrumentor, errorReporter, analytics, snykCli)
	openSourceScanner = oss.New(instrumentor, errorReporter, analytics, snykCli)
	snykCodeScanner = code.NewSnykCode(snykCodeBundleUploader, snykApiClient, errorReporter, analytics)
	environmentInitializer = preconditions.New(authenticator, errorReporter)
}

func analyticsFactory(apiClient code.SnykApiClient) ux.Analytics {
	var a ux.Analytics
	user, err := apiClient.GetActiveUser()
	if err != nil || user.Id == "" {
		if err == nil {
			err = errors.New("cannot retrieve active user, configuring noop analytics")
		} else {
			err = errors.Wrap(err, "cannot retrieve active user, configuring noop analytics")
		}
		errorReporter.CaptureError(err)
		a = ux.NewTestAnalytics()
	} else {
		a = segment.NewSegmentClient(user.Id, ux.Eclipse) // todo: Don't hardcode Eclipse here
	}
	return a
}

//TODO move out of prod logic
func TestInit(t *testing.T) {
	initMutex.Lock()
	defer initMutex.Unlock()
	t.Helper()
	hoverService = hover.NewDefaultService(analytics)
	analytics = ux.NewTestAnalytics()
	instrumentor = performance.NewTestInstrumentor()
	errorReporter = error_reporting.NewTestErrorReporter()
	authenticator = auth.New(errorReporter)
	environmentInitializer = preconditions.New(authenticator, errorReporter)
	fakeClient := &code.FakeSnykCodeClient{}
	snykCodeClient = fakeClient
	snykCodeBundleUploader = code.NewBundler(snykCodeClient, instrumentor)
	fakeApiClient := &code.FakeApiClient{CodeEnabled: true}
	snykCodeScanner = code.NewSnykCode(snykCodeBundleUploader, fakeApiClient, errorReporter, analytics)
	scanner = snyk.NewTestScanner()
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

func ErrorReporter() error_reporting.ErrorReporter {
	initMutex.Lock()
	defer initMutex.Unlock()
	return errorReporter
}

func SnykCli() cli.Executor {
	initMutex.Lock()
	defer initMutex.Unlock()
	return snykCli
}

func HoverService() hover.Service {
	initMutex.Lock()
	defer initMutex.Unlock()
	return hoverService
}

func Scanner() snyk.Scanner {
	initMutex.Lock()
	defer initMutex.Unlock()
	return scanner
}

func EnvironmentInitializer() *preconditions.EnvironmentInitializer {
	initMutex.Lock()
	defer initMutex.Unlock()
	return environmentInitializer
}

func OpenSourceScanner() *oss.Scanner {
	initMutex.Lock()
	defer initMutex.Unlock()
	return openSourceScanner
}
