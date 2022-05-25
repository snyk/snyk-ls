package di

import (
	"sync"
	"testing"

	"github.com/snyk/snyk-ls/code"
	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/internal/observability/instrumentation"
)

var SnykCodeClient code.SnykCodeClient
var SnykCodeBundleUploader *code.BundleUploader
var SnykCode *code.SnykCode

var instrumentor instrumentation.Instrumentor

var initMutex = &sync.Mutex{}

func Init() {
	initMutex.Lock()
	defer initMutex.Unlock()
	initInfrastructure()
	initApplication()
}

func initApplication() {
	endpoint := config.CurrentConfig().CliSettings().Endpoint
	if endpoint == "" {
		endpoint = code.DefaultEndpointURL
	}
	SnykApiClient := code.NewSnykApiClient(endpoint)
	SnykCode = code.NewSnykCode(SnykCodeBundleUploader, SnykApiClient)
}

func Instrumentor() instrumentation.Instrumentor {
	initMutex.Lock()
	defer initMutex.Unlock()
	return instrumentor
}

func initInfrastructure() {
	instrumentor = &instrumentation.InstrumentorImpl{}
	SnykCodeClient = code.NewHTTPRepository(config.CurrentConfig().SnykCodeApi(), instrumentor)
	SnykCodeBundleUploader = code.NewBundler(SnykCodeClient, instrumentor)
}

//TODO move out of prod logic
func TestInit(t *testing.T) {
	initMutex.Lock()
	defer initMutex.Unlock()
	t.Helper()
	instrumentor = &instrumentation.TestInstrumentor{}
	fakeClient := &code.FakeSnykCodeClient{}
	SnykCodeClient = fakeClient
	SnykCodeBundleUploader = code.NewBundler(SnykCodeClient, instrumentor)
	fakeApiClient := &code.FakeApiClient{CodeEnabled: true}
	SnykCode = code.NewSnykCode(SnykCodeBundleUploader, fakeApiClient)
	t.Cleanup(func() {
		fakeClient.Clear()
	})
}
