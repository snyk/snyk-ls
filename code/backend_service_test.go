package code

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/pact-foundation/pact-go/dsl"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/uri"
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
	pactDir = "./pacts"
)

func TestSnykCodeBackendService_CreateBundle(t *testing.T) {
	testutil.IntegTest(t)

	s := NewHTTPRepository(config.CurrentConfig().SnykCodeApi(), &performance.TestInstrumentor{})
	files := map[sglsp.DocumentURI]BundleFile{}
	files[path1] = BundleFile{
		Hash:    util.Hash([]byte(content)),
		Content: content,
	}
	bundleHash, missingFiles, _ := s.CreateBundle(context.Background(), files)
	assert.NotNil(t, bundleHash)
	assert.NotEqual(t, "", bundleHash)
	assert.Equal(t, 0, len(missingFiles))
}

func TestSnykCodeBackendService_ExtendBundle(t *testing.T) {
	testutil.IntegTest(t)

	s := NewHTTPRepository(config.CurrentConfig().SnykCodeApi(), &performance.TestInstrumentor{})

	var removedFiles []sglsp.DocumentURI
	files := map[sglsp.DocumentURI]BundleFile{}
	files[path1] = BundleFile{
		Hash:    util.Hash([]byte(content)),
		Content: content,
	}
	bundleHash, _, _ := s.CreateBundle(context.Background(), files)
	filesExtend := map[sglsp.DocumentURI]BundleFile{}
	filesExtend[path2] = BundleFile{
		Hash:    util.Hash([]byte(content2)),
		Content: content2,
	}
	_, missingFiles, _ := s.ExtendBundle(context.Background(), bundleHash, filesExtend, removedFiles)
	assert.Equal(t, 0, len(missingFiles))
}

func TestSnykCodeBackendService_RunAnalysisIntegration(t *testing.T) {
	testutil.IntegTest(t)

	s := NewHTTPRepository(config.CurrentConfig().SnykCodeApi(), &performance.TestInstrumentor{})
	shardKey := util.Hash([]byte("/"))
	var removedFiles []sglsp.DocumentURI
	files := map[sglsp.DocumentURI]BundleFile{}
	files[path1] = BundleFile{
		Hash:    util.Hash([]byte(content)),
		Content: content,
	}
	bundleHash, _, _ := s.CreateBundle(context.Background(), files)
	filesExtend := map[sglsp.DocumentURI]BundleFile{}
	filesExtend[path2] = BundleFile{
		Hash:    util.Hash([]byte(content2)),
		Content: content2,
	}
	bundleHash, _, _ = s.ExtendBundle(context.Background(), bundleHash, filesExtend, removedFiles)

	assert.Eventually(t, func() bool {
		limitToFiles := []sglsp.DocumentURI{path1, path2}

		analysisOptions := AnalysisOptions{
			bundleHash:   bundleHash,
			shardKey:     shardKey,
			limitToFiles: limitToFiles,
			severity:     0,
		}
		d, _, callStatus, err := s.RunAnalysis(context.Background(), analysisOptions)
		if err != nil {
			return false
		}
		path1DocumentURI := uri.PathToUri(path1)
		path2DocumentURI := uri.PathToUri(path2)
		documentDiagnostic := d[path1DocumentURI]
		if callStatus.message == "COMPLETE" && documentDiagnostic != nil {
			returnValue := assert.NotEqual(t, 0, len(d[path1DocumentURI]))
			returnValue = returnValue && assert.NotEqual(t, 0, len(d[path2DocumentURI]))
			if returnValue {
				return true
			}
		}
		return false
	}, 120*time.Second, 2*time.Second)
}

// todo analysis test limit files
// todo analysis test severities

func TestSnykCodeBackendService_convert_shouldConvertSarifCodeResults(t *testing.T) {
	s := NewHTTPRepository("", &performance.TestInstrumentor{})
	bytes, _ := os.ReadFile("testdata/sarifResponse.json")

	var analysisResponse SarifResponse
	_ = json.Unmarshal(bytes, &analysisResponse)

	diags, hovers := s.convertSarifResponse(analysisResponse)
	assert.NotNil(t, diags)
	assert.NotNil(t, hovers)

	assert.Equal(t, 1, len(diags))
	assert.Equal(t, 1, len(hovers))

	u := uri.PathToUri("/server/testdata/Dummy.java")
	assert.Equal(t, 2, len(diags[u]))
}

func TestSnykCodeBackendService_GetFilters_returns(t *testing.T) {
	testutil.UnitTest(t)
	pact := testutil.Pact(t, pactDir, "SnykCodeApi")

	pact.AddInteraction().WithRequest(dsl.Request{
		Method: "GET",
		Path:   dsl.String("/filters"),
		Headers: dsl.MapMatcher{
			"Content-Type":    dsl.String("application/json"),
			"snyk-request-id": dsl.Regex("fc763eba-0905-41c5-a27f-3934ab26786c", `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
		},
	}).WillRespondWith(dsl.Response{
		Status: 200,
		Headers: dsl.MapMatcher{
			"Content-Type": dsl.String("application/json"),
		},
		Body: dsl.Match(filtersResponse{}),
	})

	test := func() error {
		s := NewHTTPRepository(fmt.Sprintf("http://localhost:%d", pact.Server.Port), &performance.TestInstrumentor{})
		if _, _, err := s.GetFilters(context.Background()); err != nil {
			return err
		}

		return nil
	}

	err := pact.Verify(test)

	assert.NoError(t, err)
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
