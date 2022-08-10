package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/adrg/xdg"
	"github.com/stretchr/testify/assert"
)

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

func Test_FindBinaries(t *testing.T) {
	javaBinary := getJavaBinaryName()
	mavenBinary := getMavenBinaryName()
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

		c := New()
		c.AddBinaryLocationsToPath([]string{dir})

		assert.Contains(t, os.Getenv("JAVA_HOME"), dir)
	})

	t.Run("search for binary in default places", func(t *testing.T) {
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

		defaultDirs := []string{filepath.Dir(javaHome)}

		java := (&Config{defaultDirs: defaultDirs}).findBinary(getJavaBinaryName())

		assert.Equal(t, file.Name(), java)
	})

	t.Run("search for maven in path", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("MAVEN_HOME", "")
		binDir := filepath.Join(dir, "bin")
		t.Setenv("PATH", binDir)
		err := os.MkdirAll(binDir, 0700)
		if err != nil {
			t.Fatal(err)
		}
		file, err := os.Create(filepath.Join(binDir, mavenBinary))
		_ = file.Chmod(0700)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()

		New()

		assert.Contains(t, os.Getenv("PATH"), binDir)
	})
}
