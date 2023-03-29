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

package code

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/util"
)

const (
	path1   = "/AnnotatorTest.java"
	path2   = "/AnnotatorTest2.java"
	content = `public class AnnotatorTest {
  public static void delay(long millis) {
    try {
      Thread.sleep(millis);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
  }
}`
	content2 = `public class AnnotatorTest2 {
  public static void delay(long millis) {
    try {
      Thread.sleep(millis);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
  }
}`
)

func clientFunc() *http.Client {
	return config.CurrentConfig().Engine().GetNetworkAccess().GetHttpClient()
}

func TestSnykCodeBackendService_CreateBundle(t *testing.T) {
	testutil.SmokeTest(t)

	s := NewHTTPRepository(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), clientFunc)
	files := map[string]string{}
	randomAddition := fmt.Sprintf("\n public void random() { System.out.println(\"%d\") }", time.Now().UnixMicro())
	files[path1] = util.Hash([]byte(content + randomAddition))
	bundleHash, missingFiles, _ := s.CreateBundle(context.Background(), files)
	assert.NotNil(t, bundleHash)
	assert.NotEqual(t, "", bundleHash)
	assert.Equal(t, 1, len(missingFiles))
}

func TestSnykCodeBackendService_ExtendBundle(t *testing.T) {
	testutil.SmokeTest(t)
	s := NewHTTPRepository(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), clientFunc)
	var removedFiles []string
	files := map[string]string{}
	files[path1] = util.Hash([]byte(content))
	bundleHash, _, _ := s.CreateBundle(context.Background(), files)
	filesExtend := createTestExtendMap()

	bundleHash, missingFiles, _ := s.ExtendBundle(context.Background(), bundleHash, filesExtend, removedFiles)

	assert.Equal(t, 0, len(missingFiles))
	assert.NotEmpty(t, bundleHash)
}

func createTestExtendMap() map[string]BundleFile {
	filesExtend := map[string]BundleFile{}

	filesExtend[path1] = BundleFile{
		Hash:    util.Hash([]byte(content)),
		Content: content,
	}
	filesExtend[path2] = BundleFile{
		Hash:    util.Hash([]byte(content2)),
		Content: content2,
	}
	return filesExtend
}

func TestSnykCodeBackendService_RunAnalysisSmoke(t *testing.T) {
	testutil.SmokeTest(t)
	config.CurrentConfig().SetSnykCodeEnabled(true)

	s := NewHTTPRepository(performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter(), clientFunc)
	shardKey := util.Hash([]byte("/"))
	var removedFiles []string
	files := map[string]string{}
	files[path1] = util.Hash([]byte(content))
	bundleHash, _, _ := s.CreateBundle(context.Background(), files)
	filesExtend := createTestExtendMap()
	bundleHash, missingFiles, _ := s.ExtendBundle(context.Background(), bundleHash, filesExtend, removedFiles)
	assert.Len(t, missingFiles, 0, "all files should be uploaded now")

	assert.Eventually(t, func() bool {
		limitToFiles := []string{path1, path2}

		analysisOptions := AnalysisOptions{
			bundleHash:   bundleHash,
			shardKey:     shardKey,
			limitToFiles: limitToFiles,
			severity:     0,
		}
		issues, callStatus, err := s.RunAnalysis(context.Background(), analysisOptions, "")
		if err != nil {
			return false
		}
		if callStatus.message == "COMPLETE" && issues != nil {
			return assert.NotEqual(t, 0, len(issues))
		}
		return false
	}, 120*time.Second, 2*time.Second)
}

// todo analysis test limit files
// todo analysis test severities
