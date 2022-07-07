package code

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	"github.com/snyk/snyk-ls/domain/snyk"
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

func TestSnykCodeBackendService_CreateBundle(t *testing.T) {
	testutil.SmokeTest(t)

	s := NewHTTPRepository(config.CurrentConfig().SnykCodeApi(), performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter())
	files := map[string]string{}
	files[path1] = util.Hash([]byte(content))
	bundleHash, missingFiles, _ := s.CreateBundle(context.Background(), files)
	assert.NotNil(t, bundleHash)
	assert.NotEqual(t, "", bundleHash)
	assert.Equal(t, 0, len(missingFiles))
}

func TestSnykCodeBackendService_ExtendBundle(t *testing.T) {
	testutil.SmokeTest(t)
	s := NewHTTPRepository(config.CurrentConfig().SnykCodeApi(), performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter())
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

	s := NewHTTPRepository(config.CurrentConfig().SnykCodeApi(), performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter())
	shardKey := util.Hash([]byte("/"))
	var removedFiles []string
	files := map[string]string{}
	files[path1] = util.Hash([]byte(content))
	bundleHash, _, _ := s.CreateBundle(context.Background(), files)
	filesExtend := createTestExtendMap()
	bundleHash, missingFiles, _ := s.ExtendBundle(context.Background(), bundleHash, filesExtend, removedFiles)
	assert.Len(t, missingFiles, 0, "all files should be uploaded now")

	assert.Eventually(t, func() bool {
		limitToFiles := []sglsp.DocumentURI{path1, path2}

		analysisOptions := AnalysisOptions{
			bundleHash:   bundleHash,
			shardKey:     shardKey,
			limitToFiles: limitToFiles,
			severity:     0,
		}
		issues, callStatus, err := s.RunAnalysis(context.Background(), analysisOptions)
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

func TestSnykCodeBackendService_convert_shouldConvertIssues(t *testing.T) {
	s := NewHTTPRepository("", performance.NewTestInstrumentor(), error_reporting.NewTestErrorReporter())
	bytes, _ := os.ReadFile("testdata/sarifResponse.json")

	var analysisResponse SarifResponse
	_ = json.Unmarshal(bytes, &analysisResponse)

	issues := s.convertSarifResponse(analysisResponse)
	assert.NotNil(t, issues)

	path := "/server/testdata/Dummy.java"
	assert.Equal(t, 2, len(issues))
	assert.Equal(
		t,
		snyk.Issue{
			ID:               "java/DontUsePrintStackTrace",
			Range:            snyk.Range{Start: snyk.Position{Line: 5, Character: 6}, End: snyk.Position{Line: 5, Character: 7}},
			Message:          "Printing the stack trace of java.lang.InterruptedException. Production code should not use printStackTrace. (Snyk)",
			IssueType:        snyk.CodeSecurityVulnerability,
			Severity:         snyk.Low,
			AffectedFilePath: path,
			ProductLine:      "Snyk Code",
		},
		issues[0],
	)
}

func TestSnykCodeBackendService_analysisRequestBody_FillsOrgParameter(t *testing.T) {
	testutil.UnitTest(t)

	// prepare
	config.SetCurrentConfig(config.New())
	org := "test-org"
	config.CurrentConfig().SetOrganization(org)

	analysisOpts := &AnalysisOptions{
		bundleHash: "test-hash",
		shardKey:   "test-key",
		severity:   0,
	}

	expectedRequest := AnalysisRequest{
		Key: AnalysisRequestKey{
			Type:         "file",
			Hash:         analysisOpts.bundleHash,
			LimitToFiles: analysisOpts.limitToFiles,
			Shard:        analysisOpts.shardKey,
		},
		Legacy: false,
		AnalysisContext: AnalysisContext{
			Initiatior: "IDE",
			Flow:       "language-server",
			Org: AnalysisContextOrg{
				Name:        org,
				DisplayName: "unknown",
				PublicId:    "unknown",
			},
		},
	}

	// act
	bytes, err := analysisRequestBody(analysisOpts)
	if err != nil {
		assert.Fail(t, "Couldn't obtain analysis request body")
	}

	// assert
	var actualRequest AnalysisRequest
	err = json.Unmarshal(bytes, &actualRequest)
	if err != nil {
		assert.Fail(t, "Couldn't unmarshal analysis request body")
	}

	assert.Equal(t, expectedRequest, actualRequest)
}
