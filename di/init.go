package di

import (
	"github.com/snyk/snyk-ls/code"
	"github.com/snyk/snyk-ls/config"
)

var SnykCodeClient code.SnykCodeClient
var SnykCodeBundleUploader *code.BundleUploader

var SnykCode *code.SnykCode

func Init() {
	initInfrastructure()
	initApplication()
}

func initApplication() {
	endpoint := config.CurrentConfig.CliSettings().Endpoint
	if endpoint == "" {
		endpoint = code.DefaultEndpointURL
	}
	SnykApiClient := code.NewSnykApiClient(endpoint)
	SnykCode = code.NewSnykCode(SnykCodeBundleUploader, SnykApiClient)
}

func initInfrastructure() {
	SnykCodeClient = code.NewHTTPRepository(config.CurrentConfig.SnykCodeApi())
	SnykCodeBundleUploader = code.NewBundler(SnykCodeClient)
}

//TODO move out of prod logic
func TestInit() {
	fakeClient := &code.FakeSnykCodeClient{}
	SnykCodeClient = fakeClient
	SnykCodeBundleUploader = code.NewBundler(SnykCodeClient)
	fakeApiClient := &code.FakeApiClient{CodeEnabled: true}
	SnykCode = code.NewSnykCode(SnykCodeBundleUploader, fakeApiClient)
}
