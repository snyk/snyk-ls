package code

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/pact-foundation/pact-go/dsl"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/uri"
	"github.com/snyk/snyk-ls/util"
)

const (
	uri1    = "/AnnotatorTest.java"
	uri2    = "/AnnotatorTest2.java"
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

	s := NewService(environment.ApiUrl())
	files := map[sglsp.DocumentURI]BundleFile{}
	files[uri1] = BundleFile{
		Hash:    util.Hash([]byte(content)),
		Content: content,
	}
	bundleHash, missingFiles, _ := s.CreateBundle(files)
	assert.NotNil(t, bundleHash)
	assert.NotEqual(t, "", bundleHash)
	assert.Equal(t, 0, len(missingFiles))
}

func TestSnykCodeBackendService_ExtendBundle(t *testing.T) {
	testutil.IntegTest(t)

	s := NewService(environment.ApiUrl())

	var removedFiles []sglsp.DocumentURI
	files := map[sglsp.DocumentURI]BundleFile{}
	files[uri1] = BundleFile{
		Hash:    util.Hash([]byte(content)),
		Content: content,
	}
	bundleHash, _, _ := s.CreateBundle(files)
	filesExtend := map[sglsp.DocumentURI]BundleFile{}
	filesExtend[uri2] = BundleFile{
		Hash:    util.Hash([]byte(content2)),
		Content: content2,
	}
	_, missingFiles, _ := s.ExtendBundle(bundleHash, filesExtend, removedFiles)
	assert.Equal(t, 0, len(missingFiles))
}

func TestSnykCodeBackendService_RunAnalysisIntegration(t *testing.T) {
	testutil.IntegTest(t)

	s := NewService(environment.ApiUrl())
	shardKey := util.Hash([]byte("/"))
	var removedFiles []sglsp.DocumentURI
	files := map[sglsp.DocumentURI]BundleFile{}
	files[uri1] = BundleFile{
		Hash:    util.Hash([]byte(content)),
		Content: content,
	}
	bundleHash, _, _ := s.CreateBundle(files)
	filesExtend := map[sglsp.DocumentURI]BundleFile{}
	filesExtend[uri2] = BundleFile{
		Hash:    util.Hash([]byte(content2)),
		Content: content2,
	}
	bundleHash, _, _ = s.ExtendBundle(bundleHash, filesExtend, removedFiles)

	assert.Eventually(t, func() bool {
		limitToFiles := []sglsp.DocumentURI{uri1, uri2}
		d, _, callStatus, err := s.RunAnalysis(bundleHash, shardKey, limitToFiles, 0)
		if err != nil {
			return false
		}
		if callStatus == "COMPLETE" && d[uri1] != nil {
			returnValue := assert.NotEqual(t, 0, len(d[uri1]))
			returnValue = returnValue && assert.NotEqual(t, 0, len(d[uri2]))
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
	s := NewService("")
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
	pact := &dsl.Pact{
		Consumer: "SnykLS",
		Provider: "SnykCodeApi",
		PactDir:  pactDir,
	}
	defer pact.Teardown()

	pact.AddInteraction().WithRequest(dsl.Request{
		Method: "GET",
		Path:   dsl.String("/filters"),
		Headers: dsl.MapMatcher{
			"Content-Type": dsl.String("application/json"),
		},
	}).WillRespondWith(dsl.Response{
		Status: 200,
		Headers: dsl.MapMatcher{
			"Content-Type": dsl.String("application/json"),
		},
		Body: dsl.Match(filtersResponse{}),
	})

	test := func() error {
		s := NewService(fmt.Sprintf("http://localhost:%d", pact.Server.Port))
		if _, _, err := s.GetFilters(); err != nil {
			return err
		}

		return nil
	}

	err := pact.Verify(test)

	assert.NoError(t, err)
}
