package di

import (
	"sync"
	"testing"

	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/initialize"
	errorreporting "github.com/snyk/snyk-ls/domain/observability/error_reporting"
	performance2 "github.com/snyk/snyk-ls/domain/observability/performance"
	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	cli2 "github.com/snyk/snyk-ls/infrastructure/cli"
	auth2 "github.com/snyk/snyk-ls/infrastructure/cli/auth"
	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	code2 "github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/infrastructure/iac"
	"github.com/snyk/snyk-ls/infrastructure/oss"
	"github.com/snyk/snyk-ls/infrastructure/segment"
	sentry2 "github.com/snyk/snyk-ls/infrastructure/sentry"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
)

var snykApiClient snyk_api.SnykApiClient
var snykCodeClient code2.SnykCodeClient
var snykCodeBundleUploader *code2.BundleUploader
var snykCodeScanner *code2.Scanner
var infrastructureAsCodeScanner *iac.Scanner
var openSourceScanner *oss.Scanner
var environmentInitializer initialize.Initializer
var authenticator snyk.AuthenticationProvider

var instrumentor performance2.Instrumentor
var errorReporter errorreporting.ErrorReporter
var analytics ux2.Analytics
var snykCli cli2.Executor

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
	snykApiClient = snyk_api.NewSnykApiClient()
	analytics = segment.NewSegmentClient(snykApiClient, ux2.Eclipse) // todo: Don't hardcode Eclipse here
	authenticator = auth2.NewCliAuthenticationProvider(errorReporter)
	snykCli = cli2.NewExecutor(authenticator, errorReporter)
	snykCodeClient = code2.NewHTTPRepository(instrumentor, errorReporter)
	snykCodeBundleUploader = code2.NewBundler(snykCodeClient, instrumentor)
	infrastructureAsCodeScanner = iac.New(instrumentor, errorReporter, analytics, snykCli)
	openSourceScanner = oss.New(instrumentor, errorReporter, analytics, snykCli)
	snykCodeScanner = code2.New(snykCodeBundleUploader, snykApiClient, errorReporter, analytics)
	environmentInitializer = initialize.NewDelegatingInitializer(
		cli2.NewInitializer(errorReporter, install.NewInstaller(errorReporter)),
		auth2.NewInitializer(authenticator, errorReporter),
	)
}

//TODO this is becoming a hot mess we need to unify integ. test strategies
func TestInit(t *testing.T) {
	initMutex.Lock()
	defer initMutex.Unlock()
	t.Helper()
	analytics = ux2.NewTestAnalytics()
	instrumentor = performance2.NewTestInstrumentor()
	errorReporter = errorreporting.NewTestErrorReporter()
	authenticator = auth2.NewCliAuthenticationProvider(errorReporter)
	environmentInitializer = initialize.NewDelegatingInitializer(
		cli2.NewInitializer(errorReporter, install.NewInstaller(errorReporter)),
		auth2.NewInitializer(authenticator, errorReporter),
	)
	fakeClient := &code2.FakeSnykCodeClient{}
	snykCodeClient = fakeClient
	snykCli = cli2.NewExecutor(authenticator, errorReporter)
	snykCodeBundleUploader = code2.NewBundler(snykCodeClient, instrumentor)
	fakeApiClient := &snyk_api.FakeApiClient{CodeEnabled: true}
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

func ErrorReporter() errorreporting.ErrorReporter {
	initMutex.Lock()
	defer initMutex.Unlock()
	return errorReporter
}

func SnykCli() cli2.Executor {
	initMutex.Lock()
	defer initMutex.Unlock()
	return snykCli
}

func Authenticator() snyk.AuthenticationProvider {
	initMutex.Lock()
	defer initMutex.Unlock()
	return authenticator
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

func Initializer() initialize.Initializer {
	initMutex.Lock()
	defer initMutex.Unlock()
	return environmentInitializer
}

func OpenSourceScanner() *oss.Scanner {
	initMutex.Lock()
	defer initMutex.Unlock()
	return openSourceScanner
}
