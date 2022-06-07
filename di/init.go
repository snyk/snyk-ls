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
	"github.com/snyk/snyk-ls/internal/observability/user_behaviour"
)

var SnykApiClient code.SnykApiClient
var SnykCodeClient code.SnykCodeClient
var SnykCodeBundleUploader *code.BundleUploader
var SnykCode *code.SnykCode

var instrumentor performance.Instrumentor
var ErrorReporter error_reporting.ErrorReporter
var Analytics user_behaviour.Analytics

var initMutex = &sync.Mutex{}

func Init() {
	initMutex.Lock()
	defer initMutex.Unlock()
	initInfrastructure()
	initApplication()
}

func initApplication() {
	SnykCode = code.NewSnykCode(SnykCodeBundleUploader, SnykApiClient, ErrorReporter, Analytics)
}

func Instrumentor() performance.Instrumentor {
	initMutex.Lock()
	defer initMutex.Unlock()
	return instrumentor
}

func initInfrastructure() {
	ErrorReporter = sentry.NewSentryErrorReporter()
	endpoint := config.CurrentConfig().CliSettings().Endpoint
	if endpoint == "" {
		endpoint = code.DefaultEndpointURL
	}
	SnykApiClient = code.NewSnykApiClient(endpoint)
	instrumentor = sentry.NewInstrumentor()
	user, err := SnykApiClient.GetActiveUser()
	if err != nil {
		log.Warn().Err(err).Msg("Error retrieving current user")
		ErrorReporter.CaptureError(errors.Wrap(err, "cannot retrieve active user, configuring noop analytics"))
		Analytics = user_behaviour.NewNoopRecordingClient()
	}
	Analytics = segment.NewSegmentClient(user.Id, user_behaviour.Eclipse)
	SnykCodeClient = code.NewHTTPRepository(config.CurrentConfig().SnykCodeApi(), instrumentor, ErrorReporter)
	SnykCodeBundleUploader = code.NewBundler(SnykCodeClient, instrumentor)
}

//TODO move out of prod logic
func TestInit(t *testing.T) {
	initMutex.Lock()
	defer initMutex.Unlock()
	t.Helper()
	Analytics = user_behaviour.NewNoopRecordingClient()
	instrumentor = &performance.TestInstrumentor{}
	ErrorReporter = sentry.NewTestErrorReporter()
	fakeClient := &code.FakeSnykCodeClient{}
	SnykCodeClient = fakeClient
	SnykCodeBundleUploader = code.NewBundler(SnykCodeClient, instrumentor)
	fakeApiClient := &code.FakeApiClient{CodeEnabled: true}
	SnykCode = code.NewSnykCode(SnykCodeBundleUploader, fakeApiClient, ErrorReporter, Analytics)
	t.Cleanup(func() {
		fakeClient.Clear()
	})
}
