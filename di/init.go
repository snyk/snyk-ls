package di

import (
	"github.com/snyk/snyk-ls/code"
	"github.com/snyk/snyk-ls/config/environment"
)

var SnykCode code.SnykCodeService

func Init() {
	SnykCode = code.NewService(environment.ApiUrl())
	code.BundlerThatNeedsToBecomeAProp = code.Bundler{SnykCode: SnykCode}
}

//TODO move out of prod logic
func TestInit() {
	SnykCode = &code.FakeSnykCodeApiService{}
	code.BundlerThatNeedsToBecomeAProp = code.Bundler{SnykCode: SnykCode}
}
