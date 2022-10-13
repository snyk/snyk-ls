/*
 * Copyright 2022 Snyk Ltd.
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

package oss_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_Scan(t *testing.T) {
	testutil.IntegTest(t)
	config.CurrentConfig().SetFormat(config.FormatHtml)
	ctx := context.Background()
	di.TestInit(t)
	_ = di.Initializer().Init()

	workingDir, _ := os.Getwd()
	path, _ := filepath.Abs(workingDir + "/testdata/package.json")

	issues := di.OpenSourceScanner().Scan(ctx, path, "")

	assert.NotEqual(t, 0, len(issues))
	assert.True(t, strings.Contains(issues[0].Message, "<p>"))
	recorder := &di.Instrumentor().(*performance.TestInstrumentor).SpanRecorder
	spans := (*recorder).Spans()
	assert.Equal(t, "oss.Scan", spans[0].GetOperation())
}
