package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/adrg/xdg"
	"github.com/stretchr/testify/assert"
)

func TestSetToken(t *testing.T) {
	SetCurrentConfig(New()) // can't use testutil here because of cyclical imports
	oldToken := CurrentConfig().Token()
	CurrentConfig().SetToken("asdf")
	assert.Equal(t, CurrentConfig().Token(), "asdf")
	CurrentConfig().SetToken(oldToken)
}

func TestConfigDefaults(t *testing.T) {
	c := New()

	assert.True(t, c.IsTelemetryEnabled(), "Telemetry should be enabled by default")
	assert.True(t, c.IsErrorReportingEnabled(), "Error Reporting should be enabled by default")
	assert.False(t, c.IsSnykAdvisorEnabled(), "Advisor should be disabled by default")
	assert.False(t, c.IsSnykCodeEnabled(), "Snyk Code should be disabled by default")
	assert.False(t, c.IsSnykContainerEnabled(), "Snyk Container should be enabled by default")
	assert.True(t, c.IsSnykOssEnabled(), "Snyk Open Source should be enabled by default")
	assert.True(t, c.IsSnykIacEnabled(), "Snyk IaC should be enabled by default")
	assert.Equal(t, "", c.LogPath(), "Logpath should be empty by default")
	assert.Equal(t, "md", c.Format(), "Output format should be md by default")
}

func Test_SnykCodeAnalysisTimeoutReturnsTimeoutFromEnvironment(t *testing.T) {
	t.Setenv(snykCodeTimeoutKey, "1s")
	duration, _ := time.ParseDuration("1s")
	assert.Equal(t, duration, snykCodeAnalysisTimeoutFromEnv())
}

func Test_SnykCodeAnalysisTimeoutReturnsDefaultIfNoEnvVariableFound(t *testing.T) {
	t.Setenv(snykCodeTimeoutKey, "")
	duration, _ := time.ParseDuration("10m")
	assert.Equal(t, duration, snykCodeAnalysisTimeoutFromEnv())
}

func Test_updatePath(t *testing.T) {
	t.Setenv("PATH", "a")
	c := New()
	c.updatePath("b")
	assert.Contains(t, c.path, string(os.PathListSeparator)+"b")
	assert.Contains(t, c.path, "a"+string(os.PathListSeparator))
}

func Test_loadFile(t *testing.T) {
	t.Setenv("A", "")
	t.Setenv("C", "")
	os.Unsetenv("A")
	os.Unsetenv("C")
	envData := []byte("A=B\nC=D")
	file, err := os.CreateTemp(".", "config_test_loadFile")
	if err != nil {
		assert.Fail(t, "Couldn't create temp file", err)
	}
	defer func(file *os.File) {
		_ = file.Close()
		_ = os.Remove(file.Name())
	}(file)
	if err != nil {
		assert.Fail(t, "Couldn't create test file")
	}
	_, _ = file.Write(envData)
	if err != nil {
		assert.Fail(t, "Couldn't write to test file")
	}

	CurrentConfig().loadFile(file.Name())

	assert.Equal(t, "B", os.Getenv("A"))
	assert.Equal(t, "D", os.Getenv("C"))
}

func TestSnykCodeApi(t *testing.T) {
	t.Run("endpoint not provided", func(t *testing.T) {
		codeApiEndpoint, _ := getCodeApiUrlFromCustomEndpoint("")
		assert.Equal(t, "https://deeproxy.snyk.io", codeApiEndpoint)
	})

	t.Run("endpoint provided without 'app' prefix", func(t *testing.T) {
		endpoint := "https://snyk.io/api/v1"
		codeApiEndpoint, _ := getCodeApiUrlFromCustomEndpoint(endpoint)
		assert.Equal(t, "https://deeproxy.snyk.io", codeApiEndpoint)
	})

	t.Run("endpoint provided with 'app' prefix with v1 suffix", func(t *testing.T) {
		endpoint := "https://app.snyk.io/api/v1"
		codeApiEndpoint, _ := getCodeApiUrlFromCustomEndpoint(endpoint)
		assert.Equal(t, "https://deeproxy.snyk.io", codeApiEndpoint)
	})

	t.Run("endpoint provided with 'app' prefix without v1 suffix", func(t *testing.T) {
		endpoint := "https://app.snyk.io/api"
		codeApiEndpoint, _ := getCodeApiUrlFromCustomEndpoint(endpoint)
		assert.Equal(t, "https://deeproxy.snyk.io", codeApiEndpoint)
	})

	t.Run("endpoint provided with 'api' prefix", func(t *testing.T) {
		endpoint := "https://api.snyk.io"
		codeApiEndpoint, _ := getCodeApiUrlFromCustomEndpoint(endpoint)
		assert.Equal(t, "https://deeproxy.snyk.io", codeApiEndpoint)
	})

	t.Run("proxy endpoint provided via 'DEEPROXY_API_URL' environment variable", func(t *testing.T) {
		customDeeproxyUrl := "https://deeproxy.custom.url.snyk.io"
		t.Setenv("DEEPROXY_API_URL", customDeeproxyUrl)
		codeApiEndpoint, _ := getCodeApiUrlFromCustomEndpoint("")
		assert.Equal(t, customDeeproxyUrl, codeApiEndpoint)
	})
}

func Test_updatePathWithDefaults(t *testing.T) {
	t.Run("initialize path from environment", func(t *testing.T) {
		pathFromEnv := os.Getenv("PATH")
		c := New()
		assert.Contains(t, c.Path(), pathFromEnv)
	})

	t.Run("add to path from environment", func(t *testing.T) {
		pathFromEnv := "a"
		t.Setenv("PATH", pathFromEnv)
		c := New()
		c.updatePath("b")
		assert.Contains(t, c.path, pathSeparator+"b")
		assert.Contains(t, c.path, pathFromEnv+pathSeparator)
	})

	t.Run("automatically add /usr/local/bin on linux and macOS", func(t *testing.T) {
		if //goland:noinspection GoBoolExpressions
		runtime.GOOS == windows {
			t.Skipf("only added to the path on linux and macOS, this is windows")
		}
		c := New()
		assert.Contains(t, c.Path(), pathSeparator+"/usr/local/bin")
	})

	t.Run("automatically add /bin on linux and macOS", func(t *testing.T) {
		if //goland:noinspection GoBoolExpressions
		runtime.GOOS == windows {
			t.Skipf("only added to the path on linux and macOS, this is windows")
		}
		c := New()
		assert.Contains(t, c.Path(), pathSeparator+"/bin")
	})

	t.Run("automatically add $HOME/bin on linux and macOS", func(t *testing.T) {
		if //goland:noinspection GoBoolExpressions
		runtime.GOOS == windows {
			t.Skipf("only added to the path on linux and macOS, this is windows")
		}
		c := New()
		assert.Contains(t, c.Path(), pathSeparator+xdg.Home+"/bin")
	})

	t.Run("automatically add $JAVA_HOME/bin if set", func(t *testing.T) {
		javaHome := "JAVA_HOME_DUMMY"
		t.Setenv("JAVA_HOME", javaHome)
		c := New()
		assert.Contains(t, c.Path(), pathSeparator+javaHome+string(os.PathSeparator)+"bin")
	})
}

func Test_FindJava(t *testing.T) {
	javaBinary := getJavaBinaryName()
	t.Run("search for java in path", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("JAVA_HOME", "")
		binDir := filepath.Join(dir, "bin")
		t.Setenv("PATH", binDir)
		err := os.MkdirAll(binDir, 0700)
		if err != nil {
			t.Fatal(err)
		}
		file, err := os.Create(filepath.Join(binDir, javaBinary))
		_ = file.Chmod(0700)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()

		New()

		assert.Contains(t, os.Getenv("JAVA_HOME"), dir)
	})

	t.Run("search for java in default places", func(t *testing.T) {
		t.Setenv("JAVA_HOME", "")
		t.Setenv("PATH", "")

		javaHome := t.TempDir()
		err := os.MkdirAll(javaHome, 0770)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { os.RemoveAll(javaHome) }()
		binDir := filepath.Join(javaHome, "bin")
		err = os.Mkdir(binDir, 0770)
		if err != nil {
			t.Fatal(err)
		}
		file, err := os.Create(filepath.Join(binDir, javaBinary))
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		err = file.Chmod(0770)
		if err != nil {
			t.Fatal(err)
		}
		defaultJavaDirs := javaDirs
		defer func() {
			javaDirs = defaultJavaDirs
		}()

		javaDirs = []string{filepath.Dir(javaHome)}

		java := (&Config{}).findJava()

		assert.Equal(t, file.Name(), java)
	})
}
