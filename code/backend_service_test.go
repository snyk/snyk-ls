package code

import (
	"github.com/snyk/snyk-lsp/code/structs"
	"github.com/snyk/snyk-lsp/util"
	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"net/http"
	"os"
	"testing"
)

const (
	uri     = "/AnnotatorTest.java"
	uri2    = "/AnnotatorTest2.java"
	content = `public class AnnotatorTest {\n public static 
						void delay(long millis) {\n try {\n Thread.sleep(millis);\n }
						catch (InterruptedException e) {\n e.printStackTrace();\n    }\n  }\n}\n`
	content2 = `public class AnnotatorTest {\n public static 
						void delay(long millis) {\n try {\n Thread.sleep(millis);\n }
						catch (InterruptedException e) {\n e.printStackTrace();\n    }\n  }\n}\n`
)

func TestSnykCodeBackendService_CreateBundle(t *testing.T) {
	s := &SnykCodeBackendService{
		client: http.Client{},
	}
	files := map[lsp.DocumentURI]structs.File{}
	files[uri] = structs.File{
		Hash:    util.Hash(content),
		Content: content,
	}
	bundleHash, missingFiles, _ := s.CreateBundle(files)
	assert.NotNil(t, bundleHash)
	assert.NotEqual(t, "", bundleHash)
	assert.Equal(t, 0, len(missingFiles))
}

func TestSnykCodeBackendService_ExtendBundle(t *testing.T) {
	s := &SnykCodeBackendService{
		client: http.Client{},
	}
	var removedFiles []lsp.DocumentURI
	files := map[lsp.DocumentURI]structs.File{}
	files[uri] = structs.File{
		Hash:    util.Hash(content),
		Content: content,
	}
	bundleHash, _, _ := s.CreateBundle(files)
	filesExtend := map[lsp.DocumentURI]structs.File{}
	filesExtend[uri2] = structs.File{
		Hash:    util.Hash(content2),
		Content: content2,
	}
	missingFiles, _ := s.ExtendBundle(bundleHash, filesExtend, removedFiles)
	assert.Equal(t, 0, len(missingFiles))
}

func TestSnykCodeBackendService_RetrieveDiagnostics(t *testing.T) {
	s := &SnykCodeBackendService{
		client: http.Client{},
	}
	var removedFiles []lsp.DocumentURI
	files := map[lsp.DocumentURI]structs.File{}
	files[uri] = structs.File{
		Hash:    util.Hash(content),
		Content: content,
	}
	bundleHash, _, _ := s.CreateBundle(files)
	filesExtend := map[lsp.DocumentURI]structs.File{}
	filesExtend[uri2] = structs.File{
		Hash:    util.Hash(content2),
		Content: content2,
	}
	s.ExtendBundle(bundleHash, filesExtend, removedFiles)

	diagnostics, _ := s.RetrieveDiagnostics(bundleHash, nil, 0)
	assert.NotEqual(t, 0, len(diagnostics[uri]))
	assert.NotEqual(t, 0, len(diagnostics[uri2]))
}

func TestSnykCodeBackendService_token(t *testing.T) {
	os.Clearenv()
	assert.Equal(t, "", token())
	os.Setenv(TokenEnvVariable, "test")
	assert.Equal(t, "test", token())
}

// todo analysis test limit files
// todo analysis test severities
