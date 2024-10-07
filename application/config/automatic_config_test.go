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

package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/adrg/xdg"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func Test_updatePathWithDefaults(t *testing.T) {
	t.Run("initialize path from environment", func(t *testing.T) {
		pathFromEnv := os.Getenv("PATH")
		c := New()
		assert.Contains(t, c.Path(), pathFromEnv)
	})

	t.Run("automatically add /usr/local/bin on linux and macOS", func(t *testing.T) {
		if //goland:noinspection GoBoolExpressions
		runtime.GOOS == windows {
			t.Skipf("only added to the path on linux and macOS, this is windows")
		}
		c := New()
		assert.Contains(t, c.Path(), pathListSeparator+"/usr/local/bin")
	})

	t.Run("automatically add /bin on linux and macOS", func(t *testing.T) {
		if //goland:noinspection GoBoolExpressions
		runtime.GOOS == windows {
			t.Skipf("only added to the path on linux and macOS, this is windows")
		}
		c := New()
		assert.Contains(t, c.Path(), pathListSeparator+"/bin")
	})

	t.Run("automatically add $HOME/bin on linux and macOS", func(t *testing.T) {
		if //goland:noinspection GoBoolExpressions
		runtime.GOOS == windows {
			t.Skipf("only added to the path on linux and macOS, this is windows")
		}
		c := New()
		assert.Contains(t, c.Path(), pathListSeparator+xdg.Home+"/bin")
	})

	t.Run("automatically add $JAVA_HOME/bin if set", func(t *testing.T) {
		javaHome := "JAVA_HOME_DUMMY"
		t.Setenv("JAVA_HOME", javaHome)
		c := New()
		assert.Contains(t, c.Path(), pathListSeparator+javaHome+string(os.PathSeparator)+"bin")
	})
}

func Test_FindBinaries(t *testing.T) {
	javaBinary := getJavaBinaryName()
	mavenBinary := getMavenBinaryName()
	t.Run("search for java in path", func(t *testing.T) {
		dir, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}

		t.Setenv("JAVA_HOME", "")
		javaBaseDir := filepath.Join(dir, "java", "somewhere")
		binDir := filepath.Join(javaBaseDir, "bin")
		t.Setenv("PATH", binDir)
		err = os.MkdirAll(binDir, 0700)
		if err != nil {
			t.Fatal(err)
		}
		file, err := os.Create(filepath.Join(binDir, javaBinary))
		_ = file.Chmod(0700)
		if err != nil {
			t.Fatal(err)
		}
		defer func(file *os.File) { _ = file.Close() }(file)

		anotherDir := filepath.Join(dir, "z", "another", javaBinary)
		err = os.MkdirAll(anotherDir, 0700)
		if err != nil {
			t.Fatal(err)
		}

		c := New()
		c.AddBinaryLocationsToPath([]string{dir})

		assert.Contains(t, os.Getenv("JAVA_HOME"), javaBaseDir)
	})

	t.Run("search for binary in default places", func(t *testing.T) {
		t.Setenv("JAVA_HOME", "")
		t.Setenv("PATH", "")

		javaHome := t.TempDir()
		err := os.MkdirAll(javaHome, 0770)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.RemoveAll(javaHome) }()
		binDir := filepath.Join(javaHome, "bin")
		err = os.Mkdir(binDir, 0770)
		if err != nil {
			t.Fatal(err)
		}
		file, err := os.Create(filepath.Join(binDir, javaBinary))
		if err != nil {
			t.Fatal(err)
		}
		defer func(file *os.File) { _ = file.Close() }(file)
		err = file.Chmod(0770)
		if err != nil {
			t.Fatal(err)
		}

		nop := zerolog.Nop()
		c := &Config{defaultDirs: []string{filepath.Dir(javaHome)}, logger: &nop}

		java := c.findBinary(getJavaBinaryName())

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
		defer func(file *os.File) { _ = file.Close() }(file)

		New()

		assert.Contains(t, os.Getenv("PATH"), binDir)
	})
}
