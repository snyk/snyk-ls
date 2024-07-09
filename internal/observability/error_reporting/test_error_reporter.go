/*
 * © 2022 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package error_reporting

import (
	"github.com/snyk/snyk-ls/application/config"
)

type testErrorReporter struct{}

func (s *testErrorReporter) CaptureErrorAndReportAsIssue(path string, err error) bool {
	logger := config.CurrentConfig().Logger()
	logger.Log().Err(err).Msg("An error has been captured by the testing error reporter")
	return true
}

func NewTestErrorReporter() ErrorReporter {
	return &testErrorReporter{}
}

func (s *testErrorReporter) FlushErrorReporting() {
}

func (s *testErrorReporter) CaptureError(err error) bool {
	logger := config.CurrentConfig().Logger()
	logger.Log().Err(err).Msg("An error has been captured by the testing error reporter")
	return true
}
