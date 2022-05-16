package di

import (
	"github.com/snyk/snyk-ls/code"
	"github.com/snyk/snyk-ls/config/environment"
)

var SnykCodeClient code.SnykCodeClient
var SnykCodeBundleUploader *code.BundleUploader

var SnykCode *code.SnykCode

func Init() {
	initInfrastructure()
	initDomain()
}

func initDomain() {
	SnykCode = code.NewSnykCode(SnykCodeBundleUploader)
}

func initInfrastructure() {
	SnykCodeClient = code.NewHTTPRepository(environment.ApiUrl())
	SnykCodeBundleUploader = code.NewBundler(SnykCodeClient)
}

//TODO move out of prod logic
func TestInit() {
	SnykCodeClient = &code.FakeSnykCodeClient{}
	SnykCodeBundleUploader = code.NewBundler(SnykCodeClient)
	SnykCode = code.NewSnykCode(SnykCodeBundleUploader)
}
