package code

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/util"
)

const (
	uri     = "/AnnotatorTest.java"
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
)

func TestSnykCodeBackendService_CreateBundle(t *testing.T) {
	if !environment.RunIntegTest {
		return
	}
	s := &SnykCodeBackendService{
		client: http.Client{},
	}
	files := map[sglsp.DocumentURI]File{}
	files[uri] = File{
		Hash:    util.Hash(content),
		Content: content,
	}
	bundleHash, missingFiles, _ := s.CreateBundle(files)
	assert.NotNil(t, bundleHash)
	assert.NotEqual(t, "", bundleHash)
	assert.Equal(t, 0, len(missingFiles))
}

func TestSnykCodeBackendService_ExtendBundle(t *testing.T) {
	if !environment.RunIntegTest {
		return
	}
	s := &SnykCodeBackendService{
		client: http.Client{},
	}
	var removedFiles []sglsp.DocumentURI
	files := map[sglsp.DocumentURI]File{}
	files[uri] = File{
		Hash:    util.Hash(content),
		Content: content,
	}
	bundleHash, _, _ := s.CreateBundle(files)
	filesExtend := map[sglsp.DocumentURI]File{}
	filesExtend[uri2] = File{
		Hash:    util.Hash(content2),
		Content: content2,
	}
	_, missingFiles, _ := s.ExtendBundle(bundleHash, filesExtend, removedFiles)
	assert.Equal(t, 0, len(missingFiles))
}

func TestSnykCodeBackendService_RunAnalysisIntegration(t *testing.T) {
	if !environment.RunIntegTest {
		return
	}
	s := &SnykCodeBackendService{
		client: http.Client{},
	}
	var removedFiles []sglsp.DocumentURI
	files := map[sglsp.DocumentURI]File{}
	files[uri] = File{
		Hash:    util.Hash(content),
		Content: content,
	}
	bundleHash, _, _ := s.CreateBundle(files)
	filesExtend := map[sglsp.DocumentURI]File{}
	filesExtend[uri2] = File{
		Hash:    util.Hash(content2),
		Content: content2,
	}
	bundleHash, _, _ = s.ExtendBundle(bundleHash, filesExtend, removedFiles)

	assert.Eventually(t, func() bool {
		limitToFiles := []sglsp.DocumentURI{uri, uri2}
		d, _, callStatus, err := s.RunAnalysis(bundleHash, limitToFiles, 0)
		if err != nil {
			return false
		}
		if callStatus == "COMPLETE" && d[uri] != nil {
			returnValue := assert.NotEqual(t, 0, len(d[uri]))
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

func TestSnykCodeBackendService_convert_shouldConvertCodeResults(t *testing.T) {
	s := &SnykCodeBackendService{
		client: http.Client{},
	}
	bytes, _ := os.ReadFile("testdata/analysisResponse.json")
	var analysisResponse AnalysisResponse
	_ = json.Unmarshal(bytes, &analysisResponse)
	diags, lenses := s.convertLegacyResponse(analysisResponse)
	assert.NotNil(t, diags)
	assert.NotNil(t, lenses)
	assert.Equal(t, 1, len(diags))
	assert.Equal(t, 1, len(lenses))
}

func TestSnykCodeBackendService_convert_shouldConvertSarifCodeResults(t *testing.T) {
	s := &SnykCodeBackendService{
		client: http.Client{},
	}
	bytes, _ := os.ReadFile("testdata/sarifResponse.json")
	var analysisResponse SarifResponse
	_ = json.Unmarshal(bytes, &analysisResponse)
	diags, lenses := s.convertSarifResponse(analysisResponse)
	assert.NotNil(t, diags)
	assert.NotNil(t, lenses)
	assert.Equal(t, 1, len(diags))
	uri := sglsp.DocumentURI("file:///server/testdata/Dummy.java")
	assert.Equal(t, 2, len(diags[uri]))
	assert.Equal(t, 1, len(lenses))
	assert.Equal(t, 2, len(lenses[uri]))
}
