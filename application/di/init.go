package di

import (
	"sync"
	"testing"

	"github.com/pkg/errors"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	error_reporting2 "github.com/snyk/snyk-ls/domain/observability/error_reporting"
	performance2 "github.com/snyk/snyk-ls/domain/observability/performance"
	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	code2 "github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/infrastructure/iac"
	"github.com/snyk/snyk-ls/infrastructure/oss"
	"github.com/snyk/snyk-ls/infrastructure/segment"
	sentry2 "github.com/snyk/snyk-ls/infrastructure/sentry"
	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/internal/cli/auth"
	"github.com/snyk/snyk-ls/internal/preconditions"
)

var snykApiClient code2.SnykApiClient
var snykCodeClient code2.SnykCodeClient
var snykCodeBundleUploader *code2.BundleUploader
var snykCodeScanner *code2.Scanner
var infrastructureAsCodeScanner *iac.Scanner
var openSourceScanner *oss.Scanner
var environmentInitializer *preconditions.EnvironmentInitializer
var authenticator *auth.Authenticator

var instrumentor performance2.Instrumentor
var errorReporter error_reporting2.ErrorReporter
var analytics ux2.Analytics
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
	scanner = snyk.NewDelegatingScanner(
		environmentInitializer,
		instrumentor,
		analytics,
		snykCodeScanner,
		infrastructureAsCodeScanner,
		openSourceScanner,
	)
}

func initInfrastructure() {
	errorReporter = sentry2.NewSentryErrorReporter()
	instrumentor = sentry2.NewInstrumentor()
	endpoint := config.CurrentConfig().CliSettings().Endpoint
	if endpoint == "" {
		endpoint = code2.DefaultEndpointURL
	}
	snykApiClient = code2.NewSnykApiClient(endpoint)
	analytics = analyticsFactory(snykApiClient)
	authenticator = auth.New(errorReporter)
	snykCli = cli.NewExecutor(authenticator)
	snykCodeClient = code2.NewHTTPRepository(config.CurrentConfig().SnykCodeApi(), instrumentor, errorReporter)
	snykCodeBundleUploader = code2.NewBundler(snykCodeClient, instrumentor)
	infrastructureAsCodeScanner = iac.New(instrumentor, errorReporter, analytics, snykCli)
	openSourceScanner = oss.New(instrumentor, errorReporter, analytics, snykCli)
	snykCodeScanner = code2.New(snykCodeBundleUploader, snykApiClient, errorReporter, analytics)
	environmentInitializer = preconditions.New(authenticator, errorReporter)
}

func analyticsFactory(apiClient code2.SnykApiClient) ux2.Analytics {
	var a ux2.Analytics
	user, err := apiClient.GetActiveUser()
	if err != nil || user.Id == "" {
		if err == nil {
			err = errors.New("cannot retrieve active user, configuring noop analytics")
		} else {
			err = errors.Wrap(err, "cannot retrieve active user, configuring noop analytics")
		}
		errorReporter.CaptureError(err)
		a = ux2.NewTestAnalytics()
	} else {
		a = segment.NewSegmentClient(user.Id, ux2.Eclipse) // todo: Don't hardcode Eclipse here
	}
	return a
}

//TODO this is becoming a hot mess we need to unify integ. test strategies
func TestInit(t *testing.T) {
	initMutex.Lock()
	defer initMutex.Unlock()
	t.Helper()
	analytics = ux2.NewTestAnalytics()
	instrumentor = performance2.NewTestInstrumentor()
	errorReporter = error_reporting2.NewTestErrorReporter()
	authenticator = auth.New(errorReporter)
	environmentInitializer = preconditions.New(authenticator, errorReporter)
	fakeClient := &code2.FakeSnykCodeClient{}
	snykCodeClient = fakeClient
	snykCli = cli.NewExecutor(authenticator)
	snykCodeBundleUploader = code2.NewBundler(snykCodeClient, instrumentor)
	fakeApiClient := &code2.FakeApiClient{CodeEnabled: true}
	snykCodeScanner = code2.New(snykCodeBundleUploader, fakeApiClient, errorReporter, analytics)
	openSourceScanner = oss.New(instrumentor, errorReporter, analytics, snykCli)
	infrastructureAsCodeScanner = iac.New(instrumentor, errorReporter, analytics, snykCli)
	scanner = snyk.NewDelegatingScanner(environmentInitializer, instrumentor, analytics, snykCodeScanner, infrastructureAsCodeScanner, openSourceScanner)
	hoverService = hover.NewDefaultService(analytics)
	t.Cleanup(func() {
		fakeClient.Clear()
	})
}

/*
TODO Accessors: This should go away, since all dependencies should be satisfied at startup-time, if needed for testing
they can be returned by the test helper for unit/integration tests
*/

func Instrumentor() performance2.Instrumentor {
	initMutex.Lock()
	defer initMutex.Unlock()
	return instrumentor
}

func ErrorReporter() error_reporting2.ErrorReporter {
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
